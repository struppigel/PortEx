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

import io.github.struppigel.parser.Interruption;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PhysicalLocation;
import io.github.struppigel.parser.StandardField;
import io.github.struppigel.parser.optheader.DataDirectoryKey;
import io.github.struppigel.parser.optheader.WindowsEntryKey;
import io.github.struppigel.parser.sections.SectionHeader;
import io.github.struppigel.parser.sections.SectionLoader;
import io.github.struppigel.parser.sections.cert.ParseContext.IssueSink;
import io.github.struppigel.parser.sections.cert.SignatureChecks.Outcome;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Checks the integrity of the Authenticode signatures of a PE file.
 * <ul>
 * <li>The image digest: the file is hashed without the checksum, the
 * certificate table entry and the certificate table, and compared with the
 * signed digest.</li>
 * <li>The messageDigest attribute: compared with the digest of the signed
 * content.</li>
 * <li>The signer signature over the signed attributes, with the key of the
 * embedded signer certificate.</li>
 * <li>The signature of every embedded certificate, with the key of its
 * embedded issuer, and the chain of the signer certificate.</li>
 * <li>Timestamps: the imprint of the signature value and the signature of the
 * timestamp signer.</li>
 * </ul>
 * VALID means integrity only: no trust, revocation or expiry policy is
 * applied. The verifier does not know which roots are trusted.
 * <p>
 * The class is stateless and thread-safe. Hashing reads the whole file, the
 * work is interruptible with {@link Thread#interrupt()}.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class AuthenticodeVerifier {

    private AuthenticodeVerifier() {
    }

    /**
     * Loads the certificate table and verifies its signatures.
     *
     * @param data the PE data
     * @return the verification, with no results if the file has no
     *         certificate table
     * @throws IOException if the file can not be read
     */
    public static AuthenticodeVerification verify(PEData data) throws IOException {
        if (!data.getOptionalHeader().maybeGetDataDirEntry(DataDirectoryKey.CERTIFICATE_TABLE).isPresent()) {
            return new AuthenticodeVerification(Collections.<VerificationResult>emptyList(),
                    Collections.<String, String>emptyMap(), Collections.<CertificateIssue>emptyList());
        }
        return verify(data, CertificateTable.load(data));
    }

    /**
     * Verifies the signatures of the certificate table.
     *
     * @param data  the PE data
     * @param table the certificate table of the file
     * @return the verification
     * @throws IOException if the file can not be read
     */
    public static AuthenticodeVerification verify(PEData data, CertificateTable table) throws IOException {
        List<AuthenticodeSignature> signatures = table.getAllSignatures();
        Set<String> digestNames = new LinkedHashSet<>();
        for (AuthenticodeSignature s : signatures) {
            s.getImageDigestAlgorithm().flatMap(AlgorithmId::getJdkName).ifPresent(digestNames::add);
        }
        Map<String, byte[]> computed = digestNames.isEmpty() ? Collections.<String, byte[]>emptyMap()
                : ImageHasher.hash(data.getFile(), excludedRanges(data, table), digestNames);
        Run run = new Run(sectionLayoutIrregular(data));
        List<VerificationResult> results = new ArrayList<>();
        for (AuthenticodeSignature s : signatures) {
            results.add(run.verifySignature(s, computed));
        }
        Map<String, String> hex = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> e : computed.entrySet()) {
            hex.put(e.getKey(), Hex.of(e.getValue()));
        }
        return new AuthenticodeVerification(results, hex, run.ctx.issues());
    }

    /**
     * @return the ranges {start, length} that are not hashed: the checksum,
     *         the certificate table entry and the certificate table
     */
    static List<long[]> excludedRanges(PEData data, CertificateTable table) {
        List<long[]> excluded = new ArrayList<>();
        StandardField checksum = data.getOptionalHeader().getField(WindowsEntryKey.CHECKSUM);
        excluded.add(new long[]{checksum.getOffset(), checksum.getSize()});
        excluded.add(new long[]{table.getTableEntryOffset(), 8});
        excluded.add(new long[]{table.getOffset(), table.getDeclaredSize()});
        return excluded;
    }

    /**
     * @return true iff the raw data of the sections has gaps or overlaps, in
     *         which case implementations of the image digest can differ
     */
    private static boolean sectionLayoutIrregular(PEData data) {
        SectionLoader loader = new SectionLoader(data);
        boolean lowAlignment = data.getOptionalHeader().isLowAlignmentMode();
        List<long[]> ranges = new ArrayList<>();
        for (SectionHeader header : data.getSectionTable().getSectionHeaders()) {
            long size = loader.getReadSize(header);
            if (size > 0) {
                long start = header.getAlignedPointerToRaw(lowAlignment);
                ranges.add(new long[]{start, start + size});
            }
        }
        ranges.sort(Comparator.comparingLong(r -> r[0]));
        for (int i = 1; i < ranges.size(); i++) {
            if (ranges.get(i)[0] != ranges.get(i - 1)[1]) {
                return true;
            }
        }
        return false;
    }

    /** The state of one verification run. */
    private static final class Run {

        private final ParseContext ctx = new ParseContext();
        private final SignatureChecks checks = new SignatureChecks();
        private final boolean irregularLayout;

        private Run(boolean irregularLayout) {
            this.irregularLayout = irregularLayout;
        }

        private VerificationResult verifySignature(AuthenticodeSignature s, Map<String, byte[]> computed) {
            Interruption.checkInterrupt();
            IssueSink sink = ctx.sink();
            String label = s.getLabel();

            VerificationStatus imageStatus = VerificationStatus.UNVERIFIABLE;
            String computedHex = null;
            Optional<AlgorithmId> algorithm = s.getImageDigestAlgorithm();
            Optional<byte[]> stored = s.getImageDigest();
            if (algorithm.isPresent() && stored.isPresent()) {
                byte[] digest = algorithm.get().getJdkName().map(computed::get).orElse(null);
                if (digest != null) {
                    computedHex = Hex.of(digest);
                    imageStatus = MessageDigest.isEqual(digest, stored.get())
                            ? VerificationStatus.VALID : VerificationStatus.INVALID;
                    if (imageStatus == VerificationStatus.INVALID) {
                        sink.add(CertificateIssueType.IMAGE_DIGEST_MISMATCH, label + ": the computed "
                                        + algorithm.get() + " image digest " + computedHex + " differs from the signed"
                                        + " digest " + Hex.of(stored.get()) + ", the file was modified after signing"
                                        + " or the signature belongs to another file"
                                        + (irregularLayout ? "; the sections have gaps or overlaps, other"
                                        + " implementations may hash them differently" : ""),
                                s.imageDigestElement().location(), AuthenticodeFieldKey.IMAGE_DIGEST);
                    }
                }
            }

            List<CertificateVerification> bagVerifications = verifyBag(s.getCertificates(), sink, label);
            Map<AuthenticodeCertificate, CertificateVerification> byCertificate = index(bagVerifications);
            VerificationStatus messageStatus = VerificationStatus.UNVERIFIABLE;
            VerificationStatus signerStatus = VerificationStatus.UNVERIFIABLE;
            CertificateChain chain = new CertificateChain(Collections.<AuthenticodeCertificate>emptyList(),
                    VerificationStatus.UNVERIFIABLE);
            List<TimestampVerification> timestamps = new ArrayList<>();
            Optional<SignerInfo> signer = s.getSigner();
            if (signer.isPresent()) {
                SignerInfo si = signer.get();
                messageStatus = checkMessageDigest(si, s.indirectDataElement(),
                        CertificateIssueType.MESSAGE_DIGEST_MISMATCH, sink, label + ": signer");
                signerStatus = checkSignerSignature(si, s.indirectDataElement(),
                        CertificateIssueType.INVALID_SIGNER_SIGNATURE, sink, label + ": signer");
                chain = buildChain(si.getSignerCertificate(), byCertificate);
                for (Timestamp t : si.getTimestamps()) {
                    timestamps.add(verifyTimestamp(t, si, byCertificate, sink, label));
                }
            }
            return new VerificationResult(s, imageStatus, computedHex, messageStatus, signerStatus, chain,
                    bagVerifications, timestamps, sink.issues());
        }

        private VerificationStatus checkMessageDigest(SignerInfo si, DerElement content,
                                                      CertificateIssueType mismatchType, IssueSink sink,
                                                      String who) {
            DerElement attribute = si.messageDigestElement();
            Optional<String> jdkName = si.getDigestAlgorithm().getJdkName();
            if (content == null || attribute == null || !jdkName.isPresent()) {
                return VerificationStatus.UNVERIFIABLE;
            }
            byte[] digest = digest(jdkName.get(), content, true);
            if (digest == null) {
                return VerificationStatus.UNVERIFIABLE;
            }
            if (MessageDigest.isEqual(digest, attribute.content())) {
                return VerificationStatus.VALID;
            }
            sink.add(mismatchType, who + ": the messageDigest attribute " + Hex.of(attribute.content())
                            + " differs from the " + si.getDigestAlgorithm() + " digest " + Hex.of(digest)
                            + " of the signed content", attribute.location(),
                    mismatchType == CertificateIssueType.INVALID_TIMESTAMP ? AuthenticodeFieldKey.TIMESTAMP
                            : AuthenticodeFieldKey.MESSAGE_DIGEST);
            return VerificationStatus.INVALID;
        }

        private VerificationStatus checkSignerSignature(SignerInfo si, DerElement content,
                                                        CertificateIssueType invalidType, IssueSink sink,
                                                        String who) {
            Optional<AuthenticodeCertificate> certificate = si.getSignerCertificate();
            if (!certificate.isPresent()) {
                return VerificationStatus.UNVERIFIABLE;
            }
            byte[] signed;
            if (si.signedAttributesElement() != null) {
                // the signature covers the DER encoding of the SET OF attributes
                signed = si.signedAttributesElement().encodedWithIdentifier(0x31);
            } else if (content != null) {
                signed = content.content();
            } else {
                return VerificationStatus.UNVERIFIABLE;
            }
            Outcome outcome = checks.verify(signed, si.getSignatureValue(), si.getSignatureAlgorithm(),
                    si.getJdkSignatureAlgorithm().orElse(null), certificate.get());
            report(outcome, invalidType, who + " signature", si.getSignatureValueLocation(), sink,
                    invalidType == CertificateIssueType.INVALID_TIMESTAMP ? AuthenticodeFieldKey.TIMESTAMP
                            : AuthenticodeFieldKey.SIGNER_SIGNATURE);
            return outcome.status;
        }

        private static void report(Outcome outcome, CertificateIssueType invalidType, String what,
                                   PhysicalLocation location, IssueSink sink, AuthenticodeFieldKey key) {
            if (outcome.status == VerificationStatus.VALID) {
                return;
            }
            CertificateIssueType type = outcome.issueType;
            if (outcome.status == VerificationStatus.INVALID && type == null) {
                type = invalidType;
            }
            if (type != null) {
                sink.add(type, what + " is " + outcome.status.name().toLowerCase() + ": " + outcome.reason,
                        location, key);
            }
        }

        private List<CertificateVerification> verifyBag(List<AuthenticodeCertificate> bag, IssueSink sink,
                                                        String label) {
            List<CertificateVerification> result = new ArrayList<>();
            for (AuthenticodeCertificate c : bag) {
                Interruption.checkInterrupt();
                List<AuthenticodeCertificate> candidates = new ArrayList<>();
                for (AuthenticodeCertificate other : bag) {
                    if (other.subjectNameElement().equalEncoding(c.issuerNameElement())
                            && candidates.size() < CertificateTable.MAX_ISSUER_CANDIDATES) {
                        candidates.add(other);
                    }
                }
                if (candidates.isEmpty()) {
                    result.add(new CertificateVerification(c, null, VerificationStatus.NOT_CHECKED));
                    continue;
                }
                CertificateVerification verification = null;
                Outcome last = null;
                boolean allInvalid = true;
                for (AuthenticodeCertificate issuer : candidates) {
                    Outcome outcome = verifyCertificate(c, issuer);
                    last = outcome;
                    if (outcome.status == VerificationStatus.VALID) {
                        verification = new CertificateVerification(c, issuer, VerificationStatus.VALID);
                        break;
                    }
                    if (outcome.status != VerificationStatus.INVALID) {
                        allInvalid = false;
                    }
                }
                if (verification == null) {
                    VerificationStatus status = allInvalid ? VerificationStatus.INVALID : VerificationStatus.UNVERIFIABLE;
                    verification = new CertificateVerification(c, candidates.get(0), status);
                    report(last, CertificateIssueType.INVALID_CERTIFICATE_SIGNATURE,
                            label + ": the signature of " + c, c.getLocation(), sink,
                            AuthenticodeFieldKey.CERTIFICATE_SIGNATURE);
                }
                result.add(verification);
            }
            return result;
        }

        private Outcome verifyCertificate(AuthenticodeCertificate c, AuthenticodeCertificate issuer) {
            byte[] signature;
            try {
                if (c.signatureValue().unusedBits() != 0) {
                    return Outcome.invalid("the signature BIT STRING has unused bits");
                }
                signature = c.signatureValue().asBitString();
            } catch (DerException e) {
                return Outcome.invalid("the signature BIT STRING is malformed");
            }
            return checks.verify(c.tbs().encoded(), signature, c.getSignatureAlgorithm(),
                    c.getSignatureAlgorithm().getJdkName().orElse(null), issuer);
        }

        private static Map<AuthenticodeCertificate, CertificateVerification> index(
                List<CertificateVerification> verifications) {
            Map<AuthenticodeCertificate, CertificateVerification> map = new IdentityHashMap<>();
            for (CertificateVerification v : verifications) {
                map.put(v.getCertificate(), v);
            }
            return map;
        }

        private static CertificateChain buildChain(Optional<AuthenticodeCertificate> start,
                                                   Map<AuthenticodeCertificate, CertificateVerification> verifications) {
            if (!start.isPresent()) {
                return new CertificateChain(Collections.<AuthenticodeCertificate>emptyList(),
                        VerificationStatus.UNVERIFIABLE);
            }
            List<AuthenticodeCertificate> chain = new ArrayList<>();
            Set<AuthenticodeCertificate> visited = Collections.newSetFromMap(new IdentityHashMap<>());
            AuthenticodeCertificate current = start.get();
            chain.add(current);
            visited.add(current);
            VerificationStatus status = VerificationStatus.VALID;
            while (chain.size() < CertificateTable.MAX_CHAIN_LENGTH) {
                CertificateVerification v = verifications.get(current);
                if (v == null || v.getStatus() == VerificationStatus.NOT_CHECKED) {
                    break;
                }
                status = combine(status, v.getStatus());
                if (current.isSelfIssued() || !v.getIssuer().isPresent()) {
                    break;
                }
                AuthenticodeCertificate issuer = v.getIssuer().get();
                if (visited.contains(issuer)) {
                    break;
                }
                chain.add(issuer);
                visited.add(issuer);
                current = issuer;
            }
            return new CertificateChain(chain, status);
        }

        private static VerificationStatus combine(VerificationStatus a, VerificationStatus b) {
            if (a == VerificationStatus.INVALID || b == VerificationStatus.INVALID) {
                return VerificationStatus.INVALID;
            }
            if (a == VerificationStatus.VALID && b == VerificationStatus.VALID) {
                return VerificationStatus.VALID;
            }
            return VerificationStatus.UNVERIFIABLE;
        }

        private TimestampVerification verifyTimestamp(Timestamp t, SignerInfo outerSigner,
                                                      Map<AuthenticodeCertificate, CertificateVerification> outer,
                                                      IssueSink sink, String label) {
            Interruption.checkInterrupt();
            String who = label + ": " + (t.getKind() == Timestamp.Kind.RFC3161 ? "RFC 3161 timestamp"
                    : "countersignature");
            VerificationStatus imprintStatus = checkImprint(t, outerSigner, sink, who);
            VerificationStatus signatureStatus = VerificationStatus.UNVERIFIABLE;
            CertificateChain chain = new CertificateChain(Collections.<AuthenticodeCertificate>emptyList(),
                    VerificationStatus.UNVERIFIABLE);
            Optional<SignerInfo> tsSigner = t.getSigner();
            if (tsSigner.isPresent()) {
                Map<AuthenticodeCertificate, CertificateVerification> verifications = new IdentityHashMap<>(outer);
                if (t.getKind() == Timestamp.Kind.RFC3161) {
                    verifications.putAll(index(verifyBag(t.getCertificates(), sink, who)));
                    VerificationStatus md = checkMessageDigest(tsSigner.get(), t.tstInfoElement(),
                            CertificateIssueType.INVALID_TIMESTAMP, sink, who + " signer");
                    VerificationStatus sig = checkSignerSignature(tsSigner.get(), t.tstInfoElement(),
                            CertificateIssueType.INVALID_TIMESTAMP, sink, who + " signer");
                    signatureStatus = combine(md, sig);
                } else {
                    signatureStatus = checkSignerSignature(tsSigner.get(), null,
                            CertificateIssueType.INVALID_TIMESTAMP, sink, who + " signer");
                }
                chain = buildChain(tsSigner.get().getSignerCertificate(), verifications);
            }
            return new TimestampVerification(t, imprintStatus, signatureStatus, chain);
        }

        /**
         * The timestamp must cover the signature value of the outer signer.
         */
        private VerificationStatus checkImprint(Timestamp t, SignerInfo outerSigner, IssueSink sink, String who) {
            Optional<AlgorithmId> algorithm = t.getImprintAlgorithm();
            DerElement imprint = t.imprintElement();
            if (!algorithm.isPresent() || imprint == null || !algorithm.get().getJdkName().isPresent()) {
                return VerificationStatus.UNVERIFIABLE;
            }
            byte[] digest = digest(algorithm.get().getJdkName().get(), outerSigner.signatureValueElement(), true);
            if (digest == null) {
                return VerificationStatus.UNVERIFIABLE;
            }
            if (MessageDigest.isEqual(digest, imprint.content())) {
                return VerificationStatus.VALID;
            }
            sink.add(CertificateIssueType.INVALID_TIMESTAMP, who + " does not cover the signature value: the"
                            + " timestamped digest " + Hex.of(imprint.content()) + " differs from " + Hex.of(digest),
                    t.getLocation(), AuthenticodeFieldKey.TIMESTAMP);
            return VerificationStatus.INVALID;
        }

        private static byte[] digest(String jdkName, DerElement element, boolean contentOnly) {
            try {
                MessageDigest md = MessageDigest.getInstance(jdkName);
                if (contentOnly) {
                    element.updateContent(md);
                } else {
                    element.updateEncoded(md);
                }
                return md.digest();
            } catch (NoSuchAlgorithmException e) {
                return null;
            }
        }
    }
}
