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
package io.github.struppigel;

import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.sections.cert.AuthenticodeCertificate;
import io.github.struppigel.parser.sections.cert.AuthenticodeSignature;
import io.github.struppigel.parser.sections.cert.AuthenticodeVerification;
import io.github.struppigel.parser.sections.cert.CertificateIssue;
import io.github.struppigel.parser.sections.cert.CertificateTable;
import io.github.struppigel.parser.sections.cert.SignerInfo;
import io.github.struppigel.parser.sections.cert.VerificationStatus;
import io.github.struppigel.parser.sections.rsrc.Resource;
import io.github.struppigel.tools.sigscanner.*;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.Writer;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * The code examples of docs/MIGRATION-6.md. They are compiled with the tests
 * so that the guide stays correct, but not run.
 */
@SuppressWarnings("unused")
public class MigrationExampleCodes {

    public static void allSignatures(File file) throws IOException {
        PEData data = PELoader.loadPE(file);
        for (SignatureMatch match : data.getSignatureMatches()) {
            System.out.println(match.getName() + " in " + match.getLocationLabel()
                    + " at 0x" + Long.toHexString(match.getOffset()));
        }
    }

    public static void signaturesByLocation(PEData data) {
        List<SignatureMatch> peid = data.getSignatureMatches(LocationKind.ENTRY_POINT, LocationKind.SECTION);
        List<SignatureMatch> overlay = data.getSignatureMatches(LocationKind.OVERLAY);
        List<SignatureMatch> resources = data.getSignatureMatches(LocationKind.RESOURCE);
        List<SignatureMatch> msdos = data.getSignatureMatches(LocationKind.MSDOS_HEADER);
    }

    public static void signaturesOfOneResource(PEData data, Resource resource) {
        long start = resource.rawBytesLocation().from();
        for (SignatureMatch match : data.getSignatureMatches(LocationKind.RESOURCE)) {
            if (match.getRegionStart() == start) {
                System.out.println(match.getName());
            }
        }
    }

    public static void matchedSignatureFields(SignatureMatch match) {
        String name = match.getName();
        long offset = match.getOffset();
        long regionStart = match.getRegionStart();
        int length = match.getLength();
        String pattern = match.getSignature().getClauses().get(0).getPattern().getSource();
        boolean atEntryPoint = match.getLocationKind() == LocationKind.ENTRY_POINT;
    }

    public static void bundledSignaturesWithoutPEData(File file) throws IOException {
        SignatureScanner scanner = DefaultSignatures.getPEScanner();
        List<SignatureMatch> matches = scanner.scan(PELoader.loadPE(file), LocationKind.ENTRY_POINT);
    }

    public static void ownPEiDDatabase(File userdb, File file) throws IOException {
        SignatureDatabase peid = PEiDImporter.load(userdb);
        peid.getWarnings().forEach(System.out::println);
        SignatureScanner scanner = new SignatureScanner(peid);
        List<SignatureMatch> matches = scanner.scan(PELoader.loadPE(file));
    }

    public static void ownPEiDDatabaseForTheOverlay(File overlaydb) throws IOException {
        // match signatures without ep_only at the start of the overlay
        PEiDImportOptions options = new PEiDImportOptions("overlay", true, false);
        SignatureDatabase db = PEiDImporter.load(overlaydb, options);
    }

    public static void convertPEiDDatabase(File userdb, File target) throws IOException {
        SignatureDatabase peid = PEiDImporter.load(userdb);
        try (Writer out = new FileWriter(target)) {
            SignatureDatabaseWriter.write(peid, out);
        }
    }

    public static void ownDatabase(File sigFile, File file) throws IOException {
        SignatureDatabase db = SignatureDatabase.load(sigFile);
        SignatureDatabase combined = SignatureDatabase.merge(DefaultSignatures.getPE(), db);
        SignatureScanner scanner = new SignatureScanner(combined);
        List<SignatureMatch> matches = scanner.scan(PELoader.loadPE(file));
    }

    public static void signatureInCode(PEData data) {
        SignatureDatabase db = SignatureDatabase.parse(
                "[My packer]\n" +
                "pattern = 60 BE ?? ?? ?? ?? 8D BE\n" +
                "at = entrypoint\n", "inline");
        List<SignatureMatch> matches = new SignatureScanner(db).scan(data);
    }

    public static void fileTypes(File file) {
        List<SignatureMatch> types = FileTypeScanner.scan(file);
        for (SignatureMatch type : types) {
            System.out.println(type.getName() + ", " + type.getLength() + " bytes matched");
        }
    }

    public static void fileTypeAtOffset(File file, long offset) throws IOException {
        byte[] window = new byte[4096];
        int read;
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            raf.seek(offset);
            read = Math.max(0, raf.read(window));
        }
        List<SignatureMatch> types = FileTypeScanner.scan(Arrays.copyOf(window, read));
    }

    public static void authenticode(File file) throws IOException {
        PEData data = PELoader.loadPE(file);
        Optional<CertificateTable> table = data.loadCertificateTable();
        if (!table.isPresent()) {
            System.out.println("not signed");
            return;
        }
        for (AuthenticodeSignature signature : table.get().getAllSignatures()) {
            Optional<AuthenticodeCertificate> signer = signature.getSigner()
                    .flatMap(SignerInfo::getSignerCertificate);
            System.out.println(signature.getLabel() + " by "
                    + signer.map(AuthenticodeCertificate::getSubjectName).orElse("unknown"));
        }
        // integrity only: the file was not modified and the signature is consistent
        Optional<AuthenticodeVerification> verification = data.loadAuthenticodeVerification();
        VerificationStatus status = verification.map(AuthenticodeVerification::getStatus)
                .orElse(VerificationStatus.NOT_CHECKED);
        for (CertificateIssue issue : table.get().getIssues()) {
            System.out.println(issue.getType() + ": " + issue.getDescription());
        }
    }

    public static void javaWrappers(File file) {
        Jar2ExeScanner scanner = new Jar2ExeScanner(file);
        for (SignatureMatch match : scanner.scan()) {
            if (match.getName().equals(Jar2ExeScanner.ZipSignature())) {
                System.out.println("zip at 0x" + Long.toHexString(match.getOffset()));
            }
        }
    }
}
