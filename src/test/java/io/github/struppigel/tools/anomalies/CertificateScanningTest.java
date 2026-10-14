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
package io.github.struppigel.tools.anomalies;

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.optheader.DataDirectoryKey;
import io.github.struppigel.parser.sections.cert.AuthenticodeFieldKey;
import io.github.struppigel.parser.sections.cert.CertificateIssueType;
import io.github.struppigel.parser.sections.cert.WinCertificateKey;
import org.testng.annotations.Test;
import scala.Option;

import java.io.File;
import java.io.IOException;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static io.github.struppigel.tools.anomalies.AnomalySubType.*;
import static org.testng.Assert.*;

/**
 * Tests that broken, manipulated and unusual certificate tables of the sample
 * files are reported as anomalies of the right type, class and key.
 *
 * @author Karsten Philipp Boris Hahn
 */
public class CertificateScanningTest {

    private static final String DIR = TestreportsReader.RESOURCE_DIR + "/";

    private static List<Anomaly> anomalies(String path) throws IOException {
        PEData data = PELoader.loadPE(new File(DIR + path));
        return PEAnomalyScanner.newInstance(data).getAnomalies();
    }

    private static Set<AnomalySubType> subtypes(List<Anomaly> anomalies) {
        return anomalies.stream().map(Anomaly::subtype).collect(Collectors.toSet());
    }

    private static void assertSubtypes(String path, AnomalySubType... expected) throws IOException {
        Set<AnomalySubType> found = subtypes(anomalies(path));
        for (AnomalySubType subtype : expected) {
            assertTrue(found.contains(subtype), path + " lacks " + subtype + ", found " + found);
        }
    }

    private static Anomaly first(List<Anomaly> anomalies, AnomalySubType subtype) {
        return anomalies.stream().filter(a -> a.subtype() == subtype).findFirst()
                .orElseThrow(() -> new AssertionError("no " + subtype));
    }

    @Test
    public void unknownRevision() throws IOException {
        List<Anomaly> anomalies = anomalies("corkami/signature.exe");
        Anomaly revision = first(anomalies, CERT_UNKNOWN_REVISION);
        assertTrue(revision instanceof FieldAnomaly);
        assertEquals(revision.key(), WinCertificateKey.REVISION);
        assertEquals(revision.getType(), AnomalyType.NON_DEFAULT);
        assertEquals(revision.locations().get(0).from(), 0x404);
        assertEquals(revision.locations().get(0).size(), 2);
        assertTrue(revision.description().startsWith("Certificate Table: "));
        // the signature is still parsed, it belongs to another file
        assertTrue(subtypes(anomalies).contains(CERT_IMAGE_DIGEST_MISMATCH));
    }

    @Test
    public void tableOverwrittenBySection() throws IOException {
        // CFF Explorer added the section .NewIT on top of the table
        assertSubtypes("Haus/cff-chrome_elf.dll", CERT_INVALID_LENGTH, CERT_UNKNOWN_REVISION, CERT_UNKNOWN_TYPE,
                CERT_TABLE_IN_SECTION, CERT_TABLE_NOT_LAST);
        Anomaly inSection = first(anomalies("Haus/cff-chrome_elf.dll"), CERT_TABLE_IN_SECTION);
        assertTrue(inSection instanceof StructureAnomaly);
        assertEquals(inSection.key(), PEStructureKey.CERTIFICATE_TABLE);
        assertTrue(inSection.description().contains(".NewIT"));
    }

    @Test
    public void shiftedPointer() throws IOException {
        assertSubtypes("Haus/DRWUI.exe", CERT_TABLE_TRUNCATED, CERT_INVALID_LENGTH, CERT_UNKNOWN_REVISION,
                CERT_UNKNOWN_TYPE, CERT_TABLE_MISPLACED);
        Anomaly misplaced = first(anomalies("Haus/DRWUI.exe"), CERT_TABLE_MISPLACED);
        assertEquals(misplaced.locations().get(0).from(), 0x82be00);
    }

    @Test
    public void tableOutsideOfTheFile() throws IOException {
        for (String path : new String[]{"ose", "Haus/pidgin_manipulated_GroupIconDirectory.exe",
                "Haus/pidgin_without_groupIconDirectory.exe", "Haus/pidgin_with_double_iconGroupEntries.exe",
                "Haus/pidgin_with_iconGroupEntry_without_icon.exe"}) {
            List<Anomaly> anomalies = anomalies(path);
            Anomaly invalid = anomalies.stream().filter(a -> a.subtype() == INVALID_DATA_DIR
                    && a.key() == DataDirectoryKey.CERTIFICATE_TABLE).findFirst()
                    .orElseThrow(() -> new AssertionError(path));
            assertTrue(invalid.description().contains("signature was probably stripped"), path);
            assertFalse(subtypes(anomalies).contains(CERT_TABLE_TRUNCATED), path);
        }
    }

    @Test
    public void tablesCutOffByTheEndOfTheFile() throws IOException {
        assertSubtypes("Haus/pidgin_manipulated_Icons.exe", CERT_TABLE_TRUNCATED, CERT_TABLE_IN_SECTION,
                CERT_UNKNOWN_REVISION, CERT_UNKNOWN_TYPE);
        assertSubtypes("Haus/pidgin_manipulated_GroupIconDirectory_withNullIcon.exe", CERT_TABLE_TRUNCATED,
                CERT_TABLE_IN_SECTION, CERT_INVALID_LENGTH, CERT_UNKNOWN_REVISION, CERT_UNKNOWN_TYPE);
        assertSubtypes("Haus/pidgin_two_icons_with_same_id.exe", CERT_TABLE_TRUNCATED, CERT_INVALID_LENGTH,
                CERT_UNKNOWN_REVISION, CERT_UNKNOWN_TYPE);
        assertSubtypes("Haus/pidgin_with_one_icon_without_IconGroupDirectoryEntry.exe", CERT_TABLE_TRUNCATED,
                CERT_INVALID_LENGTH, CERT_UNKNOWN_REVISION, CERT_UNKNOWN_TYPE);
    }

    @Test
    public void maximumAndFoldedValues() throws IOException {
        for (String path : new String[]{"corkami/maxvals.exe", "corkami/dllmaxvals.dll", "corkami/d_resource.dll",
                "corkami/foldedhdr.exe", "corkami/foldedhdrW7.exe"}) {
            assertSubtypes(path, INVALID_DATA_DIR, CERT_DIR_SIZE_EXCEEDS_FILE, CERT_DIR_NOT_ALIGNED);
            Anomaly size = first(anomalies(path), CERT_DIR_SIZE_EXCEEDS_FILE);
            assertTrue(size instanceof DataDirAnomaly, path);
            assertEquals(size.key(), DataDirectoryKey.CERTIFICATE_TABLE, path);
        }
        assertSubtypes("corkami/tinygui.exe", INVALID_DATA_DIR, CERT_DIR_SIZE_EXCEEDS_FILE);
    }

    @Test
    public void unalignedAndModified() throws IOException {
        List<Anomaly> anomalies = anomalies("testfiles/pyinstaller");
        assertTrue(subtypes(anomalies).contains(CERT_DIR_NOT_ALIGNED));
        Anomaly mismatch = first(anomalies, CERT_IMAGE_DIGEST_MISMATCH);
        assertTrue(mismatch instanceof AuthenticodeAnomaly);
        assertEquals(mismatch.key(), AuthenticodeFieldKey.IMAGE_DIGEST);
        assertEquals(mismatch.getType(), AnomalyType.WRONG);
        assertSubtypes("Haus/firefox_invalid_x64.exe", CERT_IMAGE_DIGEST_MISMATCH, CERT_SHA1_DIGEST);
        assertSubtypes("Haus/firefox_x64_manipulated.exe", CERT_MESSAGE_DIGEST_MISMATCH);
    }

    @Test
    public void selfSignedSigner() throws IOException {
        Anomaly selfSigned = first(anomalies("testfiles/nsis"), CERT_SELF_SIGNED_SIGNER);
        assertEquals(selfSigned.getType(), AnomalyType.NON_DEFAULT);
        assertEquals(selfSigned.key(), AuthenticodeFieldKey.SIGNER_CERTIFICATE);
    }

    @Test
    public void wellFormedSignaturesHaveNoMalformations() throws IOException {
        for (String path : new String[]{"testfiles/strings.exe", "testfiles/WMIX.exe", "testfiles/invalidCodeView",
                "testfiles/scriptcryptor", "Haus/firefox_x64.exe", "Haus/win_test.dll", "Haus/pidgin.exe",
                "BinaryCorpus_v2_oldCorkami/corkami/security_directory.exe"}) {
            for (Anomaly a : anomalies(path)) {
                boolean certificate = a.subtype().name().startsWith("CERT_")
                        || a.key() == DataDirectoryKey.CERTIFICATE_TABLE;
                boolean malformation = a.getType() == AnomalyType.WRONG || a.getType() == AnomalyType.STRUCTURE;
                assertFalse(certificate && malformation, path + ": " + a);
            }
        }
    }

    @Test
    public void everyIssueTypeHasASubtype() {
        for (CertificateIssueType type : CertificateIssueType.values()) {
            Option<AnomalySubType> subtype = CertificateScanning.subtypeFor(type);
            assertEquals(subtype.isEmpty(), type == CertificateIssueType.TABLE_BEYOND_EOF, type.name());
        }
        assertEquals(CertificateScanning.subtypeFor(CertificateIssueType.LIMIT_EXCEEDED).get(), EXHAUSTIVE_DATA);
    }

    @Test
    public void subtypesAreTypedAsInTheThesis() {
        Map<AnomalySubType, AnomalyType> expected = new EnumMap<>(AnomalySubType.class);
        for (AnomalySubType s : new AnomalySubType[]{CERT_DIR_NOT_ALIGNED, CERT_DIR_SIZE_EXCEEDS_FILE,
                CERT_DIR_TOO_SMALL, CERT_INVALID_LENGTH, CERT_SIGNER_NOT_VALID_AT_SIGNING_TIME,
                CERT_IMAGE_DIGEST_MISMATCH, CERT_MESSAGE_DIGEST_MISMATCH, CERT_INVALID_SIGNER_SIGNATURE,
                CERT_INVALID_CERTIFICATE_SIGNATURE, CERT_INVALID_TIMESTAMP, CERT_EXPLICIT_EC_PARAMETERS,
                CERT_INVALID_ECDSA_VALUE, CERT_WRONG_CONTENT_TYPE, CERT_DIGEST_ALGORITHM_MISMATCH,
                CERT_MISSING_SIGNED_ATTRIBUTE, CERT_NONZERO_PADDING, CERT_OVERSIZED_SERIAL, CERT_OVERSIZED_OID,
                CERT_NON_POSITIVE_SERIAL, CERT_UNEXPECTED_UNAUTH_ATTRIBUTE,
                CERT_INVALID_PAGE_HASHES}) {
            expected.put(s, AnomalyType.WRONG);
        }
        for (AnomalySubType s : new AnomalySubType[]{CERT_TABLE_TRUNCATED, CERT_TABLE_IN_HEADERS,
                CERT_TABLE_IN_SECTION, CERT_TABLE_NOT_LAST, CERT_TABLE_MISPLACED, CERT_MULTIPLE_ENTRIES,
                CERT_TABLE_EXTRA_DATA, CERT_DATA_AFTER_PKCS7, CERT_EXTRA_SIGNATURE_ELEMENT, CERT_MALFORMED_PKCS7,
                CERT_UNUSUAL_NESTING, CERT_UNUSUAL_SIGNER_COUNT, CERT_MISSING_SIGNER_CERTIFICATE,
                CERT_LARGE_UNAUTH_ATTRIBUTE, CERT_ISOLATED_CERTIFICATE}) {
            expected.put(s, AnomalyType.STRUCTURE);
        }
        for (AnomalySubType s : new AnomalySubType[]{CERT_UNKNOWN_REVISION, CERT_UNKNOWN_TYPE,
                CERT_UNSUPPORTED_TYPE, CERT_BER_ENCODING,
                CERT_SELF_SIGNED_SIGNER, CERT_UNKNOWN_UNAUTH_ATTRIBUTE,
                CERT_RELAXED_PE_MARKER_CHECK, CERT_UNSUPPORTED_ALGORITHM}) {
            expected.put(s, AnomalyType.NON_DEFAULT);
        }
        expected.put(CERT_DEPRECATED_REVISION, AnomalyType.DEPRECATED);
        expected.put(CERT_WEAK_DIGEST, AnomalyType.DEPRECATED);
        expected.put(CERT_SHA1_DIGEST, AnomalyType.DEPRECATED);
        expected.put(CERT_RESERVED_TYPE, AnomalyType.RESERVED);
        for (AnomalySubType s : AnomalySubType.values()) {
            if (s.name().startsWith("CERT_")) {
                assertEquals(s.getSuperType(), expected.get(s), s.name());
            }
        }
        assertEquals(expected.size(), CertificateIssueType.values().length - 2);
    }
}
