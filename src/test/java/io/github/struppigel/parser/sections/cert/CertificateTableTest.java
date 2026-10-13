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
import io.github.struppigel.parser.IOUtil;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.PhysicalLocation;
import io.github.struppigel.tools.ReportCreator;
import org.testng.annotations.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.testng.Assert.*;

/**
 * Parses and verifies the certificate tables of the sample files.
 *
 * @author Karsten Philipp Boris Hahn
 */
public class CertificateTableTest {

    private static final String DIR = TestreportsReader.RESOURCE_DIR + "/";

    /** samples with a valid Authenticode signature */
    private static final String[] VALID = {
            "testfiles/strings.exe", "testfiles/nsis", "testfiles/WMIX.exe", "testfiles/scriptcryptor",
            "testfiles/upc.exe_fixexports", "testfiles/invalidCodeView", "Haus/krnl_test.sys", "Haus/win_test.dll",
            "Haus/pdb_guid.exe", "Haus/dotnet_x64.dll", "Haus/osx_vb_netcore.dll", "Haus/firefox_x64.exe",
            "Haus/firefox_x64_copy1.exe", "Haus/firefox_x64_copy2.exe", "Haus/firefox_x86.exe",
            "Haus/firefox_x86_2.exe", "Haus/old_firefox_x86.exe", "Haus/chrome_elf.dll", "Haus/pidgin.exe",
            "corkami/osx_vb_netcore.dll", "BinaryCorpus_v2_oldCorkami/corkami/security_directory.exe"};

    static PEData load(String path) throws IOException {
        return PELoader.loadPE(new File(DIR + path));
    }

    private static Set<CertificateIssueType> issueTypes(List<CertificateIssue> issues) {
        return issues.stream().map(CertificateIssue::getType).collect(Collectors.toSet());
    }

    @Test
    public void stringsExe() throws Exception {
        PEData data = load("testfiles/strings.exe");
        CertificateTable table = data.loadCertificateTable().get();
        assertEquals(table.getOffset(), 0x52800);
        assertEquals(table.getDeclaredSize(), 0x2388);
        assertEquals(table.getPhysicalLocations().get(0), new PhysicalLocation(0x52800, 0x2388));
        assertEquals(table.getEntries().size(), 1);
        WinCertificate entry = table.getEntries().get(0);
        assertEquals(entry.getOffset(), 0x52800);
        assertEquals(entry.getLength(), 0x2388);
        assertEquals(entry.getRevision().get(), WinCertRevision.REVISION_2_0);
        assertEquals(entry.getCertificateType().get(), WinCertType.PKCS_SIGNED_DATA);
        assertEquals(entry.getField(WinCertificateKey.REVISION).getOffset(), 0x52804);
        assertEquals(entry.getPaddingLocation().get().size(), 7);

        AuthenticodeSignature signature = table.getPrimarySignature().get();
        assertEquals(signature.getContentType(), Oids.SPC_INDIRECT_DATA);
        assertEquals(signature.getImageDigestAlgorithm().get().getJdkName().get(), "SHA-256");
        assertEquals(signature.getCertificates().size(), 2);
        assertTrue(signature.getNestedSignatures().isEmpty());
        SignerInfo signer = signature.getSigner().get();
        AuthenticodeCertificate certificate = signer.getSignerCertificate().get();
        assertTrue(certificate.getSubjectCommonName().get().contains("Microsoft"));
        assertTrue(certificate.getIssuerName().contains("Microsoft Code Signing PCA"));
        assertTrue(certificate.getX509Certificate().isPresent());
        assertEquals(certificate.getX509Certificate().get().getSerialNumber(), certificate.getSerialNumber());
        assertEquals(certificate.getPublicKeyAlgorithm().getOid(), Oids.RSA_ENCRYPTION);
        assertEquals(certificate.getPublicKeySize(), 2048);
        assertEquals(signer.getProgramName().get(), "Strings");
        assertEquals(signer.getMoreInfoUrl().get(), "https://www.sysinternals.com");
        assertEquals(signer.getTimestamps().size(), 1);
        Timestamp timestamp = signer.getTimestamps().get(0);
        assertEquals(timestamp.getKind(), Timestamp.Kind.RFC3161);
        assertEquals(timestamp.getTime().get(), Instant.parse("2020-04-17T18:37:46.462Z"));
        assertTrue(table.getIssues().isEmpty(), table.getIssues().toString());

        AuthenticodeVerification verification = data.loadAuthenticodeVerification().get();
        assertEquals(verification.getStatus(), VerificationStatus.VALID);
        assertTrue(verification.isValid());
        VerificationResult result = verification.getPrimaryResult().get();
        assertEquals(result.getImageDigestStatus(), VerificationStatus.VALID);
        assertEquals(result.getMessageDigestStatus(), VerificationStatus.VALID);
        assertEquals(result.getSignerSignatureStatus(), VerificationStatus.VALID);
        assertEquals(result.getSignerChain().getCertificates().size(), 2);
        assertEquals(result.getTimestampVerifications().get(0).getStatus(), VerificationStatus.VALID);
        assertTrue(verification.getIssues().isEmpty());
        assertEquals(result.getComputedMessageDigest().get(), Hex.of(signer.getMessageDigest().get()));
        TimestampVerification t = result.getTimestampVerifications().get(0);
        assertEquals(t.getComputedImprint().get(), Hex.of(timestamp.getImprint().get()));
        assertEquals(t.getMessageDigestStatus(), VerificationStatus.VALID);
        assertEquals(t.getComputedMessageDigest().get(),
                Hex.of(timestamp.getSigner().get().getMessageDigest().get()));
    }

    @Test
    public void linearHashEqualsSpecificationHash() throws Exception {
        for (String path : new String[]{"testfiles/strings.exe", "testfiles/nsis", "Haus/pidgin.exe",
                "Haus/krnl_test.sys"}) {
            PEData data = load(path);
            AuthenticodeVerification verification = data.loadAuthenticodeVerification().get();
            String algorithm = verification.getComputedImageDigests().keySet().iterator().next();
            assertEquals(verification.getComputedImageDigests().get(algorithm),
                    Hex.of(SpecAuthenticodeHash.digest(data, algorithm)), path);
        }
    }

    @Test
    public void nsisLocation() throws Exception {
        CertificateTable table = load("testfiles/nsis").loadCertificateTable().get();
        assertEquals(table.getPhysicalLocations().get(0), new PhysicalLocation(0x71ee8, 0x72980 - 0x71ee8));
    }

    @Test
    public void nestedSignatures() throws Exception {
        PEData data = load("testfiles/invalidCodeView");
        CertificateTable table = data.loadCertificateTable().get();
        AuthenticodeSignature primary = table.getPrimarySignature().get();
        assertEquals(primary.getImageDigestAlgorithm().get().getOid(), Oids.SHA1);
        assertEquals(primary.getNestedSignatures().size(), 1);
        AuthenticodeSignature nested = primary.getNestedSignatures().get(0);
        assertEquals(nested.getNestingLevel(), 1);
        assertEquals(nested.getLabel(), "signature 2 (nested in 1)");
        assertEquals(nested.getImageDigestAlgorithm().get().getOid(), Oids.SHA256);
        assertEquals(table.getAllSignatures().size(), 2);
        assertEquals(primary.getSigner().get().getTimestamps().get(0).getKind(), Timestamp.Kind.COUNTERSIGNATURE);
        assertEquals(nested.getSigner().get().getTimestamps().get(0).getKind(), Timestamp.Kind.RFC3161);
        assertEquals(issueTypes(table.getIssues()), java.util.Collections.singleton(CertificateIssueType.SHA1_DIGEST));
        AuthenticodeVerification verification = data.loadAuthenticodeVerification().get();
        assertEquals(verification.getResults().size(), 2);
        for (VerificationResult r : verification.getResults()) {
            assertEquals(r.getStatus(), VerificationStatus.VALID, r.toString());
        }
        assertEquals(verification.getComputedImageDigests().keySet(),
                new java.util.HashSet<>(java.util.Arrays.asList("SHA-1", "SHA-256")));
    }

    @Test
    public void validSamplesVerify() throws Exception {
        for (String path : VALID) {
            long start = System.nanoTime();
            PEData data = load(path);
            AuthenticodeVerification verification = data.loadAuthenticodeVerification().get();
            assertEquals(verification.getStatus(), VerificationStatus.VALID, path + ": " + verification);
            for (VerificationResult r : verification.getResults()) {
                for (TimestampVerification t : r.getTimestampVerifications()) {
                    assertEquals(t.getStatus(), VerificationStatus.VALID, path + ": " + t);
                }
            }
            for (CertificateIssue issue : data.loadCertificateTable().get().getIssues()) {
                assertTrue(issue.getType() == CertificateIssueType.SHA1_DIGEST
                        || issue.getType() == CertificateIssueType.SELF_SIGNED_SIGNER, path + ": " + issue);
            }
            assertTrue(verification.getIssues().isEmpty(), path + ": " + verification.getIssues());
            assertTrue(System.nanoTime() - start < 10_000_000_000L, path + " took too long");
        }
    }

    @Test
    public void legacyCountersignatureOverBareDigest() throws Exception {
        // VeriSign and Symantec countersignatures sign the bare SHA-1 digest without DigestInfo
        VerificationResult r = load("testfiles/WMIX.exe").loadAuthenticodeVerification().get()
                .getPrimaryResult().get();
        TimestampVerification t = r.getTimestampVerifications().get(0);
        assertEquals(t.getTimestamp().getKind(), Timestamp.Kind.COUNTERSIGNATURE);
        assertEquals(t.getSignatureStatus(), VerificationStatus.VALID);
        assertEquals(t.getImprintStatus(), VerificationStatus.VALID);
        // the messageDigest attribute of a countersignature is the imprint
        assertEquals(t.getMessageDigestStatus(), VerificationStatus.VALID);
        assertEquals(t.getComputedMessageDigest().get(), t.getComputedImprint().get());
    }

    @Test
    public void modifiedFilesAreInvalid() throws Exception {
        for (String path : new String[]{"Haus/firefox_invalid_x64.exe", "Haus/firefox_invalid_x86.exe",
                "testfiles/pyinstaller", "corkami/standard.exe", "corkami/signature.exe"}) {
            AuthenticodeVerification v = load(path).loadAuthenticodeVerification().get();
            assertEquals(v.getStatus(), VerificationStatus.INVALID, path);
            assertEquals(v.getPrimaryResult().get().getImageDigestStatus(), VerificationStatus.INVALID, path);
            assertTrue(issueTypes(v.getIssues()).contains(CertificateIssueType.IMAGE_DIGEST_MISMATCH), path);
        }
        AuthenticodeVerification manipulated = load("Haus/firefox_x64_manipulated.exe")
                .loadAuthenticodeVerification().get();
        VerificationResult result = manipulated.getPrimaryResult().get();
        assertEquals(result.getMessageDigestStatus(), VerificationStatus.INVALID);
        assertNotEquals(result.getComputedMessageDigest().get(),
                Hex.of(result.getSignature().getSigner().get().getMessageDigest().get()));
        assertTrue(issueTypes(manipulated.getIssues()).contains(CertificateIssueType.MESSAGE_DIGEST_MISMATCH));
    }

    @Test
    public void pageHashes() throws Exception {
        PageHashes pageHashes = load("Haus/win_test.dll").loadCertificateTable().get().getPrimarySignature().get()
                .getPageHashes().get();
        assertTrue(pageHashes.getEntryCount() > 0);
        assertTrue(pageHashes.isWellFormed());
    }

    @Test
    public void signerIsIssuedByTheCorkamiCa() throws Exception {
        CertificateTable table = load("BinaryCorpus_v2_oldCorkami/corkami/security_directory.exe")
                .loadCertificateTable().get();
        X509Certificate ca;
        try (InputStream in = new FileInputStream(DIR + "BinaryCorpus_v2_oldCorkami/corkami/ca.crt")) {
            ca = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
        AuthenticodeCertificate signer = table.getPrimarySignature().get().getSigner().get()
                .getSignerCertificate().get();
        assertEquals(signer.getX509Certificate().get().getIssuerX500Principal(), ca.getSubjectX500Principal());
    }

    @Test
    public void unsignedFilesWithSignedPayloadsHaveNoTable() throws Exception {
        for (String path : new String[]{"testfiles/7zipsfx", "testfiles/DotNetBundle.exe", "testfiles/HelloWorld.exe"}) {
            PEData data = load(path);
            assertFalse(data.loadCertificateTable().isPresent(), path);
            assertFalse(data.loadAuthenticodeVerification().isPresent(), path);
            assertTrue(data.loadAuthenticodeSignatures().isEmpty(), path);
            assertEquals(AuthenticodeVerifier.verify(data).getStatus(), VerificationStatus.NOT_CHECKED);
        }
    }

    @Test
    public void tableOutsideOfTheFileIsEmpty() throws Exception {
        CertificateTable table = load("ose").loadCertificateTable().get();
        assertTrue(table.isEmpty());
        assertTrue(table.getPhysicalLocations().isEmpty());
        assertEquals(issueTypes(table.getIssues()), java.util.Collections.singleton(CertificateIssueType.TABLE_BEYOND_EOF));
        Optional<AuthenticodeSignature> none = table.getPrimarySignature();
        assertFalse(none.isPresent());
    }

    @Test
    public void misplacedTable() throws Exception {
        CertificateTable table = load("Haus/DRWUI.exe").loadCertificateTable().get();
        CertificateIssue misplaced = table.getIssues().stream()
                .filter(i -> i.getType() == CertificateIssueType.TABLE_MISPLACED).findFirst().get();
        assertEquals(misplaced.getLocations().get(0).from(), 0x82be00);
        assertTrue(misplaced.getDescription().contains("-0x400"));
    }

    @Test
    public void authenticodeReport() throws Exception {
        ReportCreator reporter = new ReportCreator(load("testfiles/strings.exe"));
        String report = reporter.authenticodeReport();
        assertTrue(report.contains("Authenticode Signatures"), report);
        assertTrue(report.contains("Microsoft Corporation"), report);
        assertTrue(report.contains("Integrity:                VALID" + IOUtil.NL), report);
        assertTrue(report.contains("RFC 3161 timestamp"), report);
        assertTrue(report.contains("    Imprint:          "), report);
        assertTrue(report.contains("    Message digest:   "), report);
        String invalid = new ReportCreator(load("Haus/firefox_invalid_x64.exe")).authenticodeReport();
        assertTrue(invalid.contains("  Image digest:       e51fed3f2ef8c6c099c5f9f9bd1789c33de64680 (SHA-1)"), invalid);
        assertTrue(invalid.contains("    computed:         79da1b80964d0ef4e661b74d09e4d01dfb71fa95 (INVALID)"), invalid);
        assertTrue(reporter.specialSectionReports().contains("Authenticode Signatures"));
        String header = reporter.optHeaderReport();
        assertTrue(header.contains("the certificate table address is a file offset"), header);
        assertEquals(new ReportCreator(load("testfiles/HelloWorld.exe")).authenticodeReport(), "");
        // the issues are part of the anomaly report, not repeated here
        String broken = new ReportCreator(load("Haus/DRWUI.exe")).authenticodeReport();
        assertTrue(broken.contains("WIN_CERTIFICATE 0 at 0x82c200"), broken);
        assertTrue(broken.contains("type 0x202: invalid"), broken);
        assertTrue(broken.contains("Integrity:                INVALID (the signature can not be parsed)"), broken);
        assertFalse(broken.contains("shifted"), broken);
        String stripped = new ReportCreator(load("ose")).authenticodeReport();
        assertTrue(stripped.contains("Entries:                  0"), stripped);
        assertTrue(stripped.contains("INVALID (the signature can not be parsed)"), stripped);
        assertFalse(report.contains(": invalid"), report);
    }

    @Test
    public void sectionLoaderAndInfo() throws Exception {
        PEData data = load("testfiles/strings.exe");
        CertificateTable table = new io.github.struppigel.parser.sections.SectionLoader(data).loadCertificateTable();
        assertEquals(table.getEntries().size(), 1);
        assertTrue(table.getInfo().contains("Microsoft Corporation"));
        assertEquals(data.loadAuthenticodeSignatures().size(), 1);
    }
}
