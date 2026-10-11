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

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The integrity checks of all Authenticode signatures of a PE file.
 * <p>
 * VALID means integrity only: no trust, revocation or expiry policy is
 * applied. A file with a VALID signature can still be signed by an untrusted
 * or revoked certificate.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class AuthenticodeVerification {

    private final List<VerificationResult> results;
    private final Map<String, String> computedImageDigests;
    private final List<CertificateIssue> issues;

    AuthenticodeVerification(List<VerificationResult> results, Map<String, String> computedImageDigests,
                             List<CertificateIssue> issues) {
        this.results = Collections.unmodifiableList(new ArrayList<>(results));
        this.computedImageDigests = Collections.unmodifiableMap(new LinkedHashMap<>(computedImageDigests));
        this.issues = Collections.unmodifiableList(new ArrayList<>(issues));
    }

    /**
     * @return the status of the primary signature, which Windows verifies;
     *         NOT_CHECKED if there is no primary signature
     */
    public VerificationStatus getStatus() {
        Optional<VerificationResult> primary = getPrimaryResult();
        return primary.isPresent() ? primary.get().getStatus() : VerificationStatus.NOT_CHECKED;
    }

    /**
     * @return true iff the primary signature is VALID
     */
    public boolean isValid() {
        return getStatus() == VerificationStatus.VALID;
    }

    /**
     * @return one result per signature, in the order of
     *         {@link CertificateTable#getAllSignatures()}
     */
    public List<VerificationResult> getResults() {
        return results;
    }

    /**
     * @return the result of the primary signature
     */
    public Optional<VerificationResult> getPrimaryResult() {
        for (VerificationResult r : results) {
            if (r.getSignature().getEntryIndex() == 0 && r.getSignature().getNestingLevel() == 0) {
                return Optional.of(r);
            }
        }
        return Optional.empty();
    }

    /**
     * @return the computed image digests as hex strings, keyed by the JDK
     *         digest name, e.g. "SHA-256"
     */
    public Map<String, String> getComputedImageDigests() {
        return computedImageDigests;
    }

    /**
     * @return all issues found while verifying
     */
    public List<CertificateIssue> getIssues() {
        return issues;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Authenticode verification: " + getStatus());
        for (VerificationResult r : results) {
            sb.append(System.lineSeparator()).append(r);
        }
        return sb.toString();
    }
}
