package io.github.struppigel.tools;

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.tools.sigscanner.SignatureDatabase;
import io.github.struppigel.tools.sigscanner.SignatureScanner;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class ReportCreatorTest {

    private static final String TESTFILES = TestreportsReader.RESOURCE_DIR + TestreportsReader.TEST_FILE_DIR;

    private static SignatureScanner userSignatures(String text) {
        return new SignatureScanner(SignatureDatabase.parse(text, "mine.sig"));
    }

    @Test
    public void userSignaturesAreListedWithTheirDatabase() throws IOException {
        PEData data = PELoader.loadPE(new File(TESTFILES + "/WinRar.exe"));
        // the overlay of WinRar.exe at 0x18600 is a RAR archive
        SignatureScanner user = userSignatures("[My RAR]\npattern = 'Rar!' 1A 07\nat = overlay\n\n"
                + "[My MZ]\npattern = 'MZ'\nat = msdos_header\n");
        ReportCreator reporter = new ReportCreator(data, user);

        String overlay = reporter.overlayReport();
        assertTrue(overlay.contains("My RAR at overlay+0x0 (file offset 0x18600, 6 bytes) from mine.sig"), overlay);
        String signatures = reporter.signatureReport();
        assertTrue(signatures.contains("My MZ at msdos_header+0x0 (file offset 0x0, 2 bytes) from mine.sig"), signatures);
        assertFalse(signatures.contains("My RAR"), signatures);
    }

    @Test
    public void userSignaturesWithoutMatchesChangeNothing() throws IOException {
        PEData data = PELoader.loadPE(new File(TESTFILES + "/WinRar.exe"));
        ReportCreator bundled = new ReportCreator(data);
        ReportCreator user = new ReportCreator(data, userSignatures("[Nothing]\npattern = 'no such bytes'\nin = file\n"));
        assertEquals(user.overlayReport(), bundled.overlayReport());
        assertEquals(user.signatureReport(), bundled.signatureReport());
        assertEquals(user.resourcesReport(), bundled.resourcesReport());
    }

    @Test
    public void userSignaturesInResources() throws IOException {
        PEData data = PELoader.loadPE(new File(TESTFILES + "/embedded_exe_resources"));
        ReportCreator reporter = new ReportCreator(data, userSignatures("[My resource MZ]\npattern = 'MZ'\nat = resource\n"));
        String resources = reporter.resourcesReport();
        assertTrue(resources.contains("My resource MZ ("), resources);
        assertTrue(resources.contains(" bytes, from mine.sig)"), resources);
    }
}
