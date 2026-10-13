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

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.testng.Assert.*;

/**
 * Verifies signatures that {@link TestSigner} creates, including malformed
 * and malicious ones.
 *
 * @author Karsten Philipp Boris Hahn
 */
public class SyntheticSignatureTest {

    private static final File PE32 = new File(TestreportsReader.RESOURCE_DIR + "/testfiles/HelloWorld.exe");
    private static final File PE32_PLUS = new File(TestreportsReader.RESOURCE_DIR + "/testfiles/Hello.exe");

    private Path dir;

    @BeforeClass
    public void createDirectory() throws IOException {
        dir = Files.createTempDirectory("portex-signer-test");
    }

    @AfterClass(alwaysRun = true)
    public void deleteDirectory() throws IOException {
        try (Stream<Path> files = Files.walk(dir)) {
            for (Path p : files.sorted(Comparator.reverseOrder()).collect(Collectors.toList())) {
                Files.deleteIfExists(p);
            }
        }
    }

    /** the parsed table, the verification and all issues of a signed file */
    private static final class Signed {
        private final CertificateTable table;
        private final AuthenticodeVerification verification;
        private final Set<CertificateIssueType> issues;

        private Signed(CertificateTable table, AuthenticodeVerification verification) {
            this.table = table;
            this.verification = verification;
            this.issues = Stream.concat(table.getIssues().stream(), verification.getIssues().stream())
                    .map(CertificateIssue::getType).collect(Collectors.toSet());
        }
    }

    private Signed sign(File source, Consumer<TestSigner> options) throws Exception {
        TestSigner signer = new TestSigner();
        options.accept(signer);
        PEData data = PELoader.loadPE(signer.sign(source, dir));
        CertificateTable table = CertificateTable.load(data);
        return new Signed(table, AuthenticodeVerifier.verify(data, table));
    }

    private Signed sign(Consumer<TestSigner> options) throws Exception {
        return sign(PE32, options);
    }

    @Test
    public void validRsaSignature() throws Exception {
        for (File source : new File[]{PE32, PE32_PLUS}) {
            Signed s = sign(source, o -> { });
            assertEquals(s.verification.getStatus(), VerificationStatus.VALID, s.verification.toString());
            assertTrue(s.issues.isEmpty(), s.issues.toString());
            SignerInfo signer = s.table.getPrimarySignature().get().getSigner().get();
            assertEquals(signer.getProgramName().get(), "PortEx Test");
            assertEquals(signer.getMoreInfoUrl().get(), "https://example.org");
            assertEquals(s.verification.getPrimaryResult().get().getSignerChain().getCertificates().size(), 2);
            assertTrue(s.verification.getPrimaryResult().get().getSignerChain().endsInSelfSigned());
        }
    }

    @Test
    public void validEcSignature() throws Exception {
        Signed s = sign(o -> o.keyType = TestSigner.KeyType.EC);
        assertEquals(s.verification.getStatus(), VerificationStatus.VALID, s.verification.toString());
        AuthenticodeCertificate c = s.table.getPrimarySignature().get().getSigner().get().getSignerCertificate().get();
        assertEquals(c.getNamedCurve().get(), "secp256r1");
        assertEquals(c.getPublicKeySize(), 256);
        assertFalse(c.hasExplicitCurveParameters());
    }

    @Test
    public void psychicSignatureIsRejected() throws Exception {
        // CVE-2022-21449: ECDSA r = s = 0 was accepted by Java 15 to 18
        Signed s = sign(o -> {
            o.keyType = TestSigner.KeyType.EC;
            o.zeroEcdsa = true;
        });
        assertEquals(s.verification.getStatus(), VerificationStatus.INVALID);
        assertEquals(s.verification.getPrimaryResult().get().getSignerSignatureStatus(), VerificationStatus.INVALID);
        assertTrue(s.issues.contains(CertificateIssueType.INVALID_ECDSA_VALUE), s.issues.toString());
    }

    @Test
    public void explicitCurveParametersAreReported() throws Exception {
        // CVE-2020-0601 (CurveBall)
        Signed s = sign(o -> {
            o.keyType = TestSigner.KeyType.EC;
            o.explicitEcParameters = true;
        });
        assertTrue(s.issues.contains(CertificateIssueType.EXPLICIT_EC_PARAMETERS), s.issues.toString());
        AuthenticodeCertificate c = s.table.getPrimarySignature().get().getSigner().get().getSignerCertificate().get();
        assertTrue(c.hasExplicitCurveParameters());
        assertEquals(s.verification.getPrimaryResult().get().getSignerSignatureStatus(),
                VerificationStatus.UNVERIFIABLE);
        assertEquals(s.verification.getStatus(), VerificationStatus.UNVERIFIABLE);
    }

    @Test
    public void weakDigests() throws Exception {
        Signed md5 = sign(o -> o.digest = "MD5");
        assertEquals(md5.verification.getStatus(), VerificationStatus.VALID);
        List<CertificateIssue> weak = md5.table.getIssues().stream()
                .filter(i -> i.getType() == CertificateIssueType.WEAK_DIGEST).collect(Collectors.toList());
        assertEquals(weak.size(), 1, "one issue for all usages");
        assertTrue(weak.get(0).getLocations().size() >= 2);
        Signed sha1 = sign(o -> o.digest = "SHA-1");
        assertEquals(sha1.verification.getStatus(), VerificationStatus.VALID);
        assertTrue(sha1.issues.contains(CertificateIssueType.SHA1_DIGEST));
        assertFalse(sha1.issues.contains(CertificateIssueType.WEAK_DIGEST));
    }

    @Test
    public void messageDigestMismatch() throws Exception {
        Signed s = sign(o -> o.wrongMessageDigest = true);
        assertEquals(s.verification.getPrimaryResult().get().getMessageDigestStatus(), VerificationStatus.INVALID);
        assertEquals(s.verification.getStatus(), VerificationStatus.INVALID);
        assertTrue(s.issues.contains(CertificateIssueType.MESSAGE_DIGEST_MISMATCH));
    }

    @Test
    public void wrongContentType() throws Exception {
        Signed s = sign(o -> o.wrongContentType = true);
        assertTrue(s.issues.contains(CertificateIssueType.WRONG_CONTENT_TYPE), s.issues.toString());
    }

    @Test
    public void digestAlgorithmMismatch() throws Exception {
        Signed s = sign(o -> o.digestMismatch = true);
        assertTrue(s.issues.contains(CertificateIssueType.DIGEST_ALGORITHM_MISMATCH), s.issues.toString());
    }

    @Test
    public void missingMessageDigest() throws Exception {
        Signed s = sign(o -> o.missingMessageDigest = true);
        assertTrue(s.issues.contains(CertificateIssueType.MISSING_SIGNED_ATTRIBUTE), s.issues.toString());
        assertEquals(s.verification.getPrimaryResult().get().getMessageDigestStatus(),
                VerificationStatus.UNVERIFIABLE);
    }

    @Test
    public void twoSigners() throws Exception {
        Signed s = sign(o -> o.twoSigners = true);
        assertTrue(s.issues.contains(CertificateIssueType.UNUSUAL_SIGNER_COUNT));
        assertEquals(s.table.getPrimarySignature().get().getSigners().size(), 2);
    }

    @Test
    public void missingSignerCertificate() throws Exception {
        Signed s = sign(o -> o.omitSignerCertificate = true);
        assertTrue(s.issues.contains(CertificateIssueType.MISSING_SIGNER_CERTIFICATE));
        assertEquals(s.verification.getPrimaryResult().get().getSignerSignatureStatus(),
                VerificationStatus.UNVERIFIABLE);
        assertEquals(s.verification.getStatus(), VerificationStatus.UNVERIFIABLE);
    }

    @Test
    public void unauthenticatedAttributes() throws Exception {
        Signed unknown = sign(o -> {
            o.unauthenticatedOid = "1.2.3.4.5";
            o.unauthenticatedSize = 16;
        });
        assertTrue(unknown.issues.contains(CertificateIssueType.UNKNOWN_UNAUTH_ATTRIBUTE));
        assertFalse(unknown.issues.contains(CertificateIssueType.LARGE_UNAUTH_ATTRIBUTE));
        assertEquals(unknown.verification.getStatus(), VerificationStatus.VALID);
        Signed large = sign(o -> {
            o.unauthenticatedOid = Oids.SEALING_SIGNATURE;
            o.unauthenticatedSize = 70 * 1024;
        });
        assertTrue(large.issues.contains(CertificateIssueType.LARGE_UNAUTH_ATTRIBUTE));
        assertFalse(large.issues.contains(CertificateIssueType.UNKNOWN_UNAUTH_ATTRIBUTE));
        assertEquals(large.verification.getStatus(), VerificationStatus.VALID);
    }

    @Test
    public void unauthenticatedAttributesOfCountersigners() throws Exception {
        Signed unknown = sign(o -> o.countersignerUnauthenticatedOid = "1.2.3.4.5");
        assertEquals(unknown.table.getPrimarySignature().get().getSigner().get().getTimestamps().size(), 1);
        assertTrue(unknown.issues.contains(CertificateIssueType.UNKNOWN_UNAUTH_ATTRIBUTE), unknown.issues.toString());
        assertFalse(unknown.issues.contains(CertificateIssueType.UNEXPECTED_UNAUTH_ATTRIBUTE));
        // a known type that Authenticode does not use for countersigners, its content is not parsed
        Signed nested = sign(o -> o.countersignerUnauthenticatedOid = Oids.NESTED_SIGNATURE);
        assertTrue(nested.issues.contains(CertificateIssueType.UNEXPECTED_UNAUTH_ATTRIBUTE), nested.issues.toString());
        assertFalse(nested.issues.contains(CertificateIssueType.UNKNOWN_UNAUTH_ATTRIBUTE));
        assertEquals(nested.verification.getPrimaryResult().get().getImageDigestStatus(), VerificationStatus.VALID);
    }

    @Test
    public void signedAttributeTypesAsUnauthenticated() throws Exception {
        for (String oid : new String[]{Oids.INTENT_TO_SEAL, Oids.PLATFORM_MANIFEST_BINARY_ID}) {
            Signed s = sign(o -> o.unauthenticatedOid = oid);
            assertTrue(s.issues.contains(CertificateIssueType.UNEXPECTED_UNAUTH_ATTRIBUTE), oid + " " + s.issues);
            assertEquals(s.verification.getStatus(), VerificationStatus.VALID);
        }
    }

    @Test
    public void sealing() throws Exception {
        Signed unsealed = sign(o -> o.unauthenticatedOid = Oids.SEALING_SIGNATURE);
        assertTrue(unsealed.issues.contains(CertificateIssueType.UNEXPECTED_UNAUTH_ATTRIBUTE), unsealed.issues.toString());
        Signed sealed = sign(o -> {
            o.unauthenticatedOid = Oids.SEALING_SIGNATURE;
            o.intentToSeal = true;
        });
        assertTrue(sealed.issues.isEmpty(), sealed.issues.toString());
        assertEquals(sealed.verification.getStatus(), VerificationStatus.VALID);
    }

    @Test
    public void malformedRetryCount() throws Exception {
        // the retry count is an INTEGER, not an OCTET STRING
        Signed s = sign(o -> {
            o.unauthenticatedOid = Oids.SPC_ENCRYPTED_DIGEST_RETRY_COUNT;
            o.unauthenticatedSize = 16;
        });
        assertTrue(s.issues.contains(CertificateIssueType.MALFORMED_PKCS7), s.issues.toString());
        assertEquals(s.verification.getStatus(), VerificationStatus.VALID);
    }

    @Test
    public void extraElements() throws Exception {
        List<Consumer<TestSigner>> options = Arrays.asList(o -> o.extraAttributeElement = true,
                o -> o.extraSignerInfoElement = true, o -> o.extraSignedDataElement = true);
        for (Consumer<TestSigner> option : options) {
            Signed s = sign(option);
            assertEquals(s.issues, Collections.singleton(CertificateIssueType.EXTRA_SIGNATURE_ELEMENT));
            assertEquals(s.verification.getStatus(), VerificationStatus.VALID);
        }
    }

    @Test
    public void relaxedMarkerCheck() throws Exception {
        Signed s = sign(o -> o.relaxedMarker = true);
        assertTrue(s.issues.contains(CertificateIssueType.RELAXED_PE_MARKER_CHECK));
        assertEquals(s.verification.getStatus(), VerificationStatus.VALID);
    }

    @Test
    public void nestedSignatures() throws Exception {
        Signed one = sign(o -> o.nestingDepth = 1);
        assertEquals(one.table.getAllSignatures().size(), 2);
        assertFalse(one.issues.contains(CertificateIssueType.UNUSUAL_NESTING));
        for (VerificationResult r : one.verification.getResults()) {
            assertEquals(r.getStatus(), VerificationStatus.VALID);
        }
        Signed two = sign(o -> o.nestingDepth = 2);
        assertEquals(two.table.getAllSignatures().size(), 3);
        assertTrue(two.issues.contains(CertificateIssueType.UNUSUAL_NESTING));
        Signed deep = sign(o -> o.nestingDepth = 6);
        assertEquals(deep.table.getAllSignatures().size(), CertificateTable.MAX_NESTING_DEPTH + 1);
        assertTrue(deep.issues.contains(CertificateIssueType.LIMIT_EXCEEDED));
    }

    @Test
    public void isolatedCertificate() throws Exception {
        Signed s = sign(o -> o.isolatedCertificate = true);
        assertTrue(s.issues.contains(CertificateIssueType.ISOLATED_CERTIFICATE), s.issues.toString());
        assertEquals(s.verification.getStatus(), VerificationStatus.VALID);
    }

    @Test
    public void longSerialNumber() throws Exception {
        Signed s = sign(o -> o.longSerial = true);
        assertTrue(s.issues.contains(CertificateIssueType.OVERSIZED_SERIAL));
        assertEquals(s.verification.getStatus(), VerificationStatus.VALID);
    }

    @Test
    public void berEncodingIsReportedAndStillValid() throws Exception {
        Signed s = sign(o -> o.nonMinimalLength = true);
        assertTrue(s.issues.contains(CertificateIssueType.BER_ENCODING));
        assertTrue(s.table.getPrimarySignature().get().isBerEncoded());
        assertEquals(s.verification.getStatus(), VerificationStatus.VALID);
    }
}
