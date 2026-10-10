package io.github.struppigel.tools;

import org.testng.annotations.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.testng.Assert.assertEquals;
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
        assertTrue(output.contains("version: 0.12.15"));
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