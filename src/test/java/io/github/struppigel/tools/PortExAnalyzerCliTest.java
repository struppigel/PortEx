package io.github.struppigel.tools;

import io.github.struppigel.TestreportsReader;
import org.testng.annotations.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Comparator;
import java.util.stream.Collectors;
import java.util.stream.Stream;
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
            String output = assertExitCode(1, inputFile.toString());
            assertTrue(output.contains("The given file is no PE file!"), output);
            assertFalse(output.contains("--repair"), output);
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
    public void pictureOfTheWholeFileUsesTheNewVisualizer() throws Exception {
        Path image = Files.createTempFile("portex-picture", ".png");
        try {
            assertExitCode(0, "-p", image.toString(), WINRAR);
            BufferedImage picture = ImageIO.read(image.toFile());
            // 64 columns of 4 pixels for each of the 3 tracks, the offset ruler and the legend
            assertTrue(picture.getWidth() >= 90 + 3 * (4 + 64 * 4) + 4 + 220, "width " + picture.getWidth());
            assertTrue(picture.getHeight() <= 1000 && picture.getHeight() > 400, "height " + picture.getHeight());
            // the dark background of the offset ruler is only drawn by the new visualizer
            assertEquals(picture.getRGB(1, 1) & 0xFFFFFF, 0x202020);
            assertExitCode(0, "-p", image.toString(), "-bps", "4096", WINRAR);
        } finally {
            Files.deleteIfExists(image);
        }
    }

    @Test
    public void pictureWithVisOverlayIsWritten() throws Exception {
        Path image = Files.createTempFile("portex-picture-overlay", ".png");
        Path overlay = Files.createTempFile("portex-overlay", ".txt");
        try {
            Files.write(overlay, "{\n  \"offset\": \"0x400\",\n  \"size\": \"0x100\"\n}\n".getBytes());
            assertExitCode(0, "-p", image.toString(), "--visoverlay", overlay.toString(), WINRAR);
            assertTrue(Files.size(image) > 0);
        } finally {
            Files.deleteIfExists(image);
            Files.deleteIfExists(overlay);
        }
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
    public void dumpCertificatesWritesSignatureAndCertificates() throws Exception {
        Path dir = Files.createTempDirectory("portex-dump-test");
        Path copy = dir.resolve("strings.exe");
        Files.copy(new File(TestreportsReader.RESOURCE_DIR + "/testfiles/strings.exe").toPath(), copy);
        try {
            String output = assertExitCode(0, "--dump", "certificates", copy.toString());
            File dumps = dir.resolve("portex.dumps").toFile();
            File p7b = new File(dumps, "0.signature.p7b");
            assertTrue(p7b.exists(), output);
            // the raw table holds the WIN_CERTIFICATE header, the signature and the padding
            File table = new File(dumps, "certificate_table.bin");
            assertTrue(table.exists(), output);
            assertTrue(table.length() >= p7b.length() + 8, table.length() + " " + p7b.length());
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            try (InputStream in = new FileInputStream(p7b)) {
                assertEquals(factory.generateCertificates(in).size(), 2);
            }
            File[] certificates = dumps.listFiles((d, name) -> name.endsWith(".cer"));
            assertEquals(certificates.length, 2, output);
            for (File cer : certificates) {
                try (InputStream in = new FileInputStream(cer)) {
                    assertTrue(factory.generateCertificate(in) instanceof X509Certificate);
                }
            }
        } finally {
            try (Stream<Path> files = Files.walk(dir)) {
                for (Path p : files.sorted(Comparator.reverseOrder()).collect(Collectors.toList())) {
                    Files.deleteIfExists(p);
                }
            }
        }
    }

    @Test
    public void dumpCertificatesOfUnsignedFile() throws Exception {
        Path dir = Files.createTempDirectory("portex-dump-test");
        Path copy = dir.resolve("HelloWorld.exe");
        Files.copy(new File(TestreportsReader.RESOURCE_DIR + "/testfiles/HelloWorld.exe").toPath(), copy);
        try {
            String output = assertExitCode(0, "--dump", "certificates", copy.toString());
            assertTrue(output.contains("No certificate table found."), output);
        } finally {
            try (Stream<Path> files = Files.walk(dir)) {
                for (Path p : files.sorted(Comparator.reverseOrder()).collect(Collectors.toList())) {
                    Files.deleteIfExists(p);
                }
            }
        }
    }

    @Test
    public void unknownOptionReturnsFailure() throws Exception {
        assertExitCode(1, "--unknown-option");
    }

    @Test
    public void repairOptionWasRemoved() throws Exception {
        String output = assertExitCode(1, "--repair", WINRAR);
        assertTrue(output.contains("Unknown option --repair"), output);
    }

    @Test
    public void missingSignatureFolderReturnsFailure() throws Exception {
        Path missing = Files.createTempDirectory("portex-missing-sigs");
        Files.delete(missing);
        String output = assertExitCode(1, "--sigs", missing.toString(), WINRAR);
        assertTrue(output.contains("Signature folder not found: " + missing.toAbsolutePath()), output);
    }

    @Test
    public void userSignaturesMatchFilesThatAreNoPEFiles() throws Exception {
        Path sigs = Files.createTempDirectory("portex-sigs");
        Path input = Files.createTempFile("portex-rar", ".bin");
        try {
            Files.write(sigs.resolve("mine.sig"),
                    "[My RAR]\npattern = 'Rar!' 1A 07\nat = file\n".getBytes(StandardCharsets.UTF_8));
            Files.write(sigs.resolve("broken.sig"),
                    "[Broken]\npattern = 0G\nat = file\n".getBytes(StandardCharsets.UTF_8));
            Files.write(input, new byte[] {'R', 'a', 'r', '!', 0x1A, 0x07, 0, 0});
            String output = assertExitCode(1, "--sigs", sigs.toString(), input.toString());
            assertTrue(output.contains("Matches of your signatures:"), output);
            assertTrue(output.contains("* My RAR at file+0x0 (file offset 0x0, 6 bytes) from mine.sig"), output);
            assertTrue(output.contains("Warning: broken.sig:2:"), output);
        } finally {
            Files.deleteIfExists(input);
            try (Stream<Path> files = Files.walk(sigs)) {
                for (Path p : files.sorted(Comparator.reverseOrder()).collect(Collectors.toList())) {
                    Files.deleteIfExists(p);
                }
            }
        }
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