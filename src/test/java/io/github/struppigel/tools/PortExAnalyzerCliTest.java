package io.github.struppigel.tools;

import io.github.struppigel.TestreportsReader;
import org.testng.annotations.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class PortExAnalyzerCliTest {

    @Test
    public void missingInputReturnsFailure() throws Exception {
        Path missingFile = Files.createTempFile("portex-missing-input", ".exe");
        Files.delete(missingFile);
        assertExitCode(1, missingFile.toString());
    }

    @Test
    public void nonPeInputReturnsFailure() throws Exception {
        Path inputFile = Files.createTempFile("portex-non-pe-input", ".bin");
        try {
            Files.write(inputFile, new byte[] {1, 2, 3, 4});
            assertExitCode(1, inputFile.toString());
        } finally {
            Files.deleteIfExists(inputFile);
        }
    }

    @Test
    public void emptyInputReturnsFailure() throws Exception {
        Path inputFile = Files.createTempFile("portex-empty-input", ".bin");
        try {
            assertExitCode(1, inputFile.toString());
        } finally {
            Files.deleteIfExists(inputFile);
        }
    }

    @Test
    public void directoryInputReturnsFailure() throws Exception {
        Path inputDirectory = Files.createTempDirectory("portex-directory-input");
        try {
            assertExitCode(1, inputDirectory.toString());
        } finally {
            Files.deleteIfExists(inputDirectory);
        }
    }

    @Test
    public void versionRequestReturnsSuccess() throws Exception {
        String output = assertExitCode(0, "--version");
        assertTrue(output.contains("version: 0.13.0"));
        assertTrue(output.contains("last update: 11. October 2026"));
    }

    private static final String WINRAR = TestreportsReader.RESOURCE_DIR + TestreportsReader.TEST_FILE_DIR
            + "/WinRar.exe";

    @Test
    public void locationListsStructuresInnermostFirst() throws Exception {
        String output = assertExitCode(0, "-l", "0x3c", WINRAR);
        assertTrue(output.contains("0x3c: MSDOS Header [0x0,0x40) < Headers [0x0,0x400)"), output);
    }

    @Test
    public void locationAcceptsAllOptionNames() throws Exception {
        String shortOutput = assertExitCode(0, "-l", "0x3c", WINRAR);
        String locOutput = assertExitCode(0, "--loc", "0x3c", WINRAR);
        String locationOutput = assertExitCode(0, "--location", "0x3c", WINRAR);
        assertEquals(locOutput, shortOutput);
        assertEquals(locationOutput, shortOutput);
    }

    @Test
    public void locationEndIsExclusive() throws Exception {
        // the PE signature of WinRar.exe is at 0x200
        String last = assertExitCode(0, "-l", "0x203", WINRAR);
        assertTrue(last.contains("0x203: PE Signature [0x200,0x204)"), last);
        String after = assertExitCode(0, "-l", "516", WINRAR);
        assertTrue(after.contains("0x204: COFF File Header"), after);
        assertFalse(after.contains("PE Signature"), after);
    }

    @Test
    public void locationShowsLegacyHints() throws Exception {
        String output = assertExitCode(0, "-l", "0x18600,0x600", WINRAR);
        assertTrue(output.contains("0x18600: Overlay [0x18600,0x12516a)"), output);
        assertTrue(output.contains("0x18600: hints: OverlayStart"), output);
        assertTrue(output.contains("0x600: Entry Point [0x600,0x601) < Section 1 (.text)"), output);
        assertTrue(output.contains("0x600: hints: Entry Point (+/-0x6000)"), output);
    }

    @Test
    public void invalidLocationReturnsFailure() throws Exception {
        String output = assertExitCode(1, "-l", "0xZZ,0x3c", WINRAR);
        assertTrue(output.contains("Invalid offset: 0xZZ"), output);
        assertTrue(output.contains("0x3c: MSDOS Header"), output);
    }

    @Test
    public void locationBeyondFileEndIsReported() throws Exception {
        String output = assertExitCode(0, "-l", "0x12516a", WINRAR);
        assertTrue(output.contains("0x12516a: beyond the end of the file (0x12516a)"), output);
    }

    @Test
    public void zoomedPictureIsWritten() throws Exception {
        Path hexImage = Files.createTempFile("portex-zoomed-hex", ".png");
        Path largeImage = Files.createTempFile("portex-zoomed", ".png");
        try {
            assertExitCode(0, "-p", hexImage.toString(), "--from", "0x0", "--to", "0x400", WINRAR);
            BufferedImage hex = ImageIO.read(hexImage.toFile());
            // 64 rows of 16 bytes, 14 pixels high
            assertEquals(hex.getHeight(), 64 * 14);
            assertExitCode(0, "-p", largeImage.toString(), "--from", "0x10000", "--to", "0x90000", WINRAR);
            BufferedImage large = ImageIO.read(largeImage.toFile());
            assertTrue(large.getHeight() <= 1000 && large.getHeight() > 400, "height " + large.getHeight());
            assertExitCode(0, "-p", largeImage.toString(), "--from", "0x10000", "-bps", "4096", WINRAR);
            assertExitCode(1, "-p", largeImage.toString(), "--from", "0x400", "--to", "0x100", WINRAR);
        } finally {
            Files.deleteIfExists(hexImage);
            Files.deleteIfExists(largeImage);
        }
    }

    @Test
    public void layoutPrintsStructureMap() throws Exception {
        String output = assertExitCode(0, "--layout", WINRAR);
        assertTrue(output.contains("Headers [0x0,0x400)"), output);
        assertTrue(output.contains("  PE Signature [0x200,0x204)"), output);
        assertTrue(output.contains("Overlay [0x18600,0x12516a)"), output);
    }

    @Test
    public void unknownOptionReturnsFailure() throws Exception {
        assertExitCode(1, "--unknown-option");
    }

    private String assertExitCode(int expected, String... arguments) throws Exception {
        File outputFile = File.createTempFile("portex-cli-output", ".log");
        List<String> command = new ArrayList<>();
        String javaExecutable = System.getProperty("os.name").toLowerCase().contains("win")
                ? "java.exe" : "java";
        command.add(new File(System.getProperty("java.home"), "bin" + File.separator + javaExecutable)
                .getAbsolutePath());
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add("io.github.struppigel.tools.PortExAnalyzer");
        command.addAll(Arrays.asList(arguments));

        try {
            Process process = new ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .redirectOutput(outputFile)
                    .start();
            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                assertTrue(false, "PortExAnalyzer did not terminate");
            }
            assertEquals(process.exitValue(), expected);
            return new String(Files.readAllBytes(outputFile.toPath()), StandardCharsets.UTF_8);
        } finally {
            Files.deleteIfExists(outputFile.toPath());
        }
    }
}