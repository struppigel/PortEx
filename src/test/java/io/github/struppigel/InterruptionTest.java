package io.github.struppigel;

import io.github.struppigel.parser.AnalysisInterruptedException;
import io.github.struppigel.parser.Interruption;
import io.github.struppigel.parser.Mapping;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.PhysRange;
import io.github.struppigel.parser.VirtRange;
import io.github.struppigel.tools.ChiSquared;
import io.github.struppigel.tools.ShannonEntropy;
import io.github.struppigel.tools.StringExtractor;
import io.github.struppigel.tools.layout.StructureMap;
import io.github.struppigel.tools.visualizer.engine.ByteStatistics;
import io.github.struppigel.tools.visualizer.engine.ProgressListener;
import io.github.struppigel.tools.sigscanner.DefaultSignatures;
import io.github.struppigel.tools.sigscanner.SignatureScanner;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;

import static org.testng.Assert.*;

/**
 * Verifies that long running analysis loops abort promptly with
 * {@link AnalysisInterruptedException} when the executing thread is
 * interrupted, and that the interrupt flag is preserved.
 */
public class InterruptionTest {

    private File randomFile;

    @BeforeClass
    public void createTestFile() throws IOException {
        randomFile = File.createTempFile("portex-interruption-test", ".bin");
        randomFile.deleteOnExit();
        byte[] chunk = new byte[8192];
        Random rand = new Random(42);
        try (FileOutputStream out = new FileOutputStream(randomFile)) {
            for (int i = 0; i < 1024; i++) { // 8 MB of random bytes
                rand.nextBytes(chunk);
                out.write(chunk);
            }
        }
    }

    @AfterClass
    public void deleteTestFile() {
        randomFile.delete();
    }

    @AfterMethod
    public void clearInterruptFlag() {
        // do not let a leftover flag poison other tests
        Thread.interrupted();
    }

    /**
     * Runs the action with the interrupt flag pre-set and asserts it aborts
     * with AnalysisInterruptedException while keeping the flag set.
     */
    private void assertAbortsWhenInterrupted(Runnable action) {
        Thread.currentThread().interrupt();
        try {
            action.run();
            fail("expected AnalysisInterruptedException");
        } catch (AnalysisInterruptedException e) {
            assertTrue(Thread.currentThread().isInterrupted(),
                    "interrupt flag must stay set");
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    public void checkInterruptIsNoopWithoutInterrupt() {
        assertFalse(Thread.currentThread().isInterrupted());
        Interruption.checkInterrupt(); // must not throw
    }

    @Test
    public void checkInterruptThrowsAndPreservesFlag() {
        assertAbortsWhenInterrupted(() -> Interruption.checkInterrupt());
    }

    @Test
    public void mappingConstructionAbortsWhenInterrupted() {
        assertAbortsWhenInterrupted(() ->
                new Mapping(new VirtRange(0, 8192), new PhysRange(0, 8192), null));
    }

    @Test
    public void entropyFileScanAborts() {
        assertAbortsWhenInterrupted(() ->
                ShannonEntropy.entropy(randomFile, 0, randomFile.length()));
    }

    @Test
    public void entropyArrayScanAborts() {
        byte[] bytes = new byte[1024 * 1024];
        assertAbortsWhenInterrupted(() -> ShannonEntropy.entropy(bytes));
    }

    @Test
    public void chiSquaredFileScanAborts() {
        assertAbortsWhenInterrupted(() ->
                ChiSquared.calculate(randomFile, 0, randomFile.length()));
    }

    @Test
    public void chiSquaredArrayScanAborts() {
        byte[] bytes = new byte[1024 * 1024];
        assertAbortsWhenInterrupted(() -> ChiSquared.calculate(bytes));
    }

    @Test
    public void signatureFullFileScanAborts() {
        SignatureScanner scanner = DefaultSignatures.getJavaWrapperScanner();
        assertAbortsWhenInterrupted(() ->
                scanner.scanFile(randomFile));
    }

    @Test
    public void byteStatisticsAborts() {
        ByteStatistics stats = new ByteStatistics(randomFile);
        assertAbortsWhenInterrupted(() -> {
            try {
                stats.compute(ProgressListener.NONE);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
        assertFalse(stats.isComplete());
    }

    @Test
    public void runningByteStatisticsStopOnInterrupt() throws InterruptedException {
        AtomicReference<Throwable> thrown = new AtomicReference<>();
        Thread worker = new Thread(() -> {
            try {
                // stop in the progress listener so that the interrupt arrives mid-scan
                new ByteStatistics(randomFile).compute((done, total) -> {
                    try {
                        Thread.sleep(50);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                });
            } catch (Throwable t) {
                thrown.set(t);
            }
        });
        worker.start();
        Thread.sleep(100);
        worker.interrupt();
        worker.join(5000);
        assertFalse(worker.isAlive(), "worker must stop after interrupt");
        assertTrue(thrown.get() instanceof AnalysisInterruptedException,
                "expected AnalysisInterruptedException but got: " + thrown.get());
    }

    @Test
    public void structureMapBuildAborts() throws IOException {
        PEData data = PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR
                + TestreportsReader.TEST_FILE_DIR + "/WinRar.exe"));
        assertAbortsWhenInterrupted(() -> StructureMap.of(data));
    }

    @Test
    public void stringExtractorAborts() {
        assertAbortsWhenInterrupted(() ->
                StringExtractor.readASCIIStrings(randomFile, 4));
    }

    /**
     * Integration style test: interrupt a worker mid-scan and require it to
     * stop within a bounded time. A full-file signature scan of 8 MB is faster
     * than the interrupt delay, so the worker scans repeatedly.
     */
    @Test
    public void runningFullFileScanStopsPromptlyOnInterrupt()
            throws InterruptedException {
        SignatureScanner scanner = DefaultSignatures.getJavaWrapperScanner();
        AtomicReference<Throwable> thrown = new AtomicReference<>();
        Thread worker = new Thread(() -> {
            try {
                while (true) {
                    scanner.scanFile(randomFile);
                }
            } catch (Throwable t) {
                thrown.set(t);
            }
        });
        worker.start();
        Thread.sleep(200); // let the scan get into the hot loop
        worker.interrupt();
        worker.join(5000);
        assertFalse(worker.isAlive(), "worker must stop after interrupt");
        assertTrue(thrown.get() instanceof AnalysisInterruptedException,
                "expected AnalysisInterruptedException but got: " + thrown.get());
    }
}
