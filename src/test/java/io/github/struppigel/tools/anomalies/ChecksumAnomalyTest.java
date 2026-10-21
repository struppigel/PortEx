package io.github.struppigel.tools.anomalies;

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.optheader.WindowsEntryKey;
import io.github.struppigel.tools.ChecksumCheck;
import io.github.struppigel.tools.ReportCreator;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

import static org.testng.Assert.*;

public class ChecksumAnomalyTest {

    /** signed and with a valid checksum */
    private static final File STRINGS = new File(TestreportsReader.RESOURCE_DIR + "/testfiles/strings.exe");

    private Path copy;

    @AfterMethod(alwaysRun = true)
    public void deleteCopy() throws IOException {
        if (copy != null) Files.deleteIfExists(copy);
    }

    /** a copy of strings.exe with the byte at the offset changed */
    private PEData modifiedCopy(long offset, byte value) throws IOException {
        copy = Files.createTempFile("portex-checksum", ".exe");
        byte[] bytes = Files.readAllBytes(STRINGS.toPath());
        bytes[(int) offset] = value;
        Files.write(copy, bytes);
        return PELoader.loadPE(copy.toFile());
    }

    private static List<Anomaly> checksumAnomalies(PEData data) {
        return PEAnomalyScanner.newInstance(data).getAnomalies().stream()
                .filter(a -> a.subtype() == AnomalySubType.INVALID_CHECKSUM).collect(Collectors.toList());
    }

    @Test
    public void validChecksumIsNoAnomaly() throws IOException {
        PEData data = PELoader.loadPE(STRINGS);
        ChecksumCheck check = data.loadChecksumCheck().get();
        assertTrue(check.isValid());
        assertEquals(check.getDescription(), "Checksum is valid (0x55d4a)");
        assertTrue(checksumAnomalies(data).isEmpty());
        assertTrue(new ReportCreator(data).optHeaderReport().contains("Checksum is valid (0x55d4a)"));
    }

    @Test
    public void changedFileHasInvalidChecksum() throws IOException {
        // the last byte of the certificate table
        PEData data = modifiedCopy(STRINGS.length() - 1, (byte) 0x11);
        ChecksumCheck check = data.loadChecksumCheck().get();
        assertTrue(check.isInvalid());
        List<Anomaly> anomalies = checksumAnomalies(data);
        assertEquals(anomalies.size(), 1);
        assertEquals(anomalies.get(0).description(), "Optional Header: checksum is invalid (0x55d4a), the actual checksum is 0x"
                + Long.toHexString(check.getActualChecksum()));
        assertEquals(anomalies.get(0).subtype().getSuperType(), AnomalyType.WRONG);
        assertTrue(new ReportCreator(data).anomalyReport().contains("Optional Header: checksum is invalid"));
    }

    @Test
    public void checksumZeroIsNotSet() throws IOException {
        long field = PELoader.loadPE(STRINGS).getOptionalHeader().getField(WindowsEntryKey.CHECKSUM).getOffset();
        copy = Files.createTempFile("portex-checksum", ".exe");
        byte[] bytes = Files.readAllBytes(STRINGS.toPath());
        for (int i = 0; i < 4; i++) bytes[(int) field + i] = 0;
        Files.write(copy, bytes);
        PEData data = PELoader.loadPE(copy.toFile());
        ChecksumCheck check = data.loadChecksumCheck().get();
        assertFalse(check.isSet());
        assertFalse(check.isInvalid());
        // the checksum field counts as zero, so the actual checksum does not change
        assertEquals(check.getDescription(), "Checksum is not set, the actual checksum is 0x55d4a");
        assertTrue(checksumAnomalies(data).isEmpty());
    }
}
