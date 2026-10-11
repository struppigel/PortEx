/*******************************************************************************
 * Copyright 2026 Karsten Philipp Boris Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package io.github.struppigel.parser.sections.cert;

import io.github.struppigel.parser.PhysicalLocation;
import io.github.struppigel.parser.StandardField;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * State of one certificate table parse: the issue collector, which removes
 * duplicates and is capped at {@link CertificateTable#MAX_ISSUES}, and the
 * counters for the signature limits.
 * <p>
 * Used by one thread only.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class ParseContext {

    private final List<CertificateIssue> issues = new ArrayList<>();
    private final Set<String> keys = new HashSet<>();
    private final CertificateFactory certificateFactory;
    private boolean issueLimitReported;
    private int signatureCount;

    ParseContext() {
        CertificateFactory factory;
        try {
            factory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            factory = null;
        }
        this.certificateFactory = factory;
    }

    /**
     * @return the JDK certificate factory, null if not available
     */
    CertificateFactory certificateFactory() {
        return certificateFactory;
    }

    /**
     * @return the number of the next signature, starting at 1
     */
    int nextSignatureNumber() {
        return ++signatureCount;
    }

    /**
     * Adds an issue unless an equal one (same type and location) exists or
     * the maximum number of issues is reached.
     *
     * @return the added issue, null if it was dropped
     */
    CertificateIssue add(CertificateIssueType type, String description, List<PhysicalLocation> locations,
                         StandardField headerField, AuthenticodeFieldKey fieldKey) {
        String key = type + "@" + (locations.isEmpty() ? "-" : locations.get(0).from() + ":"
                + locations.get(0).size());
        if (!keys.add(key)) {
            return null;
        }
        if (issues.size() >= CertificateTable.MAX_ISSUES) {
            if (!issueLimitReported) {
                issueLimitReported = true;
                issues.add(new CertificateIssue(CertificateIssueType.LIMIT_EXCEEDED,
                        "more than " + CertificateTable.MAX_ISSUES + " certificate issues, the rest is omitted",
                        Collections.<PhysicalLocation>emptyList(), null, null));
            }
            return null;
        }
        CertificateIssue issue = new CertificateIssue(type, description, locations, headerField, fieldKey);
        issues.add(issue);
        return issue;
    }

    /**
     * @return all issues in the order they were found
     */
    List<CertificateIssue> issues() {
        return Collections.unmodifiableList(new ArrayList<>(issues));
    }

    /**
     * Creates a sink that adds issues to this context and remembers the ones
     * that belong to one signature.
     */
    IssueSink sink() {
        return new IssueSink(this);
    }

    /**
     * Collects the issues of one part of the table, e.g. one signature, and
     * forwards them to the context.
     */
    static final class IssueSink {

        private final ParseContext ctx;
        private final List<CertificateIssue> own = new ArrayList<>();

        private IssueSink(ParseContext ctx) {
            this.ctx = ctx;
        }

        ParseContext context() {
            return ctx;
        }

        void add(CertificateIssueType type, String description, PhysicalLocation location,
                 AuthenticodeFieldKey fieldKey) {
            List<PhysicalLocation> locs = location == null ? Collections.<PhysicalLocation>emptyList()
                    : Collections.singletonList(location);
            add(type, description, locs, null, fieldKey);
        }

        void add(CertificateIssueType type, String description, List<PhysicalLocation> locations,
                 StandardField headerField, AuthenticodeFieldKey fieldKey) {
            CertificateIssue issue = ctx.add(type, description, locations, headerField, fieldKey);
            if (issue != null) {
                own.add(issue);
            }
        }

        /**
         * Reports a DerException as malformed signature or exceeded limit.
         */
        void addDerException(String what, DerException e) {
            PhysicalLocation loc = new PhysicalLocation(e.getFileOffset(), 1);
            if (e.isLimitExceeded()) {
                add(CertificateIssueType.LIMIT_EXCEEDED, what + ": " + e.getMessage(), loc,
                        AuthenticodeFieldKey.SIGNATURE_ENCODING);
            }
            add(CertificateIssueType.MALFORMED_PKCS7, what + " is malformed: " + e.getMessage()
                    + " at " + Hex.offset(e.getFileOffset()), loc, AuthenticodeFieldKey.SIGNATURE_ENCODING);
        }

        /**
         * Decodes an OID and reports oversized ones.
         */
        String oid(DerElement element) throws DerException {
            String oid = element.asOid();
            if (DerElement.OVERSIZED_OID.equals(oid)) {
                add(CertificateIssueType.OVERSIZED_OID, "object identifier of " + element.contentLength()
                        + " bytes at " + Hex.offset(element.fileOffset()) + " exceeds the limits",
                        element.location(), AuthenticodeFieldKey.SIGNATURE_ENCODING);
            }
            return oid;
        }

        /**
         * Parses an AlgorithmIdentifier.
         *
         * @param element the SEQUENCE { OID, parameters OPTIONAL }
         * @param digest  true if the algorithm is a digest, its JDK name is
         *                resolved then
         */
        AlgorithmId algorithm(DerElement element, boolean digest) throws DerException {
            element.expectSequence();
            String oid = oid(element.child(0));
            DerElement params = element.optChild(1).orElse(null);
            String jdkName = digest ? Algorithms.digestJdkName(oid).orElse(null)
                    : Algorithms.keyAlgorithm(oid).orElse(null);
            return new AlgorithmId(oid, jdkName, params, element.location());
        }

        List<CertificateIssue> issues() {
            return Collections.unmodifiableList(new ArrayList<>(own));
        }
    }
}
