package io.github.struppigel;

import io.github.struppigel.parser.AnalysisInterruptedException;
import io.github.struppigel.parser.Interruption;
import io.github.struppigel.tools.ChiSquared;
import io.github.struppigel.tools.ShannonEntropy;
import io.github.struppigel.tools.StringExtractor;
import io.github.struppigel.tools.sigscanner.SignatureScanner;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
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
        SignatureScanner scanner = SignatureScanner.newInstance();
        assertAbortsWhenInterrupted(() ->
                scanner.findAllEPFalseMatches(randomFile));
    }

    @Test
    public void stringExtractorAborts() {
        assertAbortsWhenInterrupted(() ->
                StringExtractor.readASCIIStrings(randomFile, 4));
    }

    /**
     * Integration style test: interrupt a worker mid-scan and require it to
     * stop within a bounded time. The full-file signature scan on 8 MB of
     * random data takes far longer than the interrupt delay.
     */
    @Test
    public void runningFullFileScanStopsPromptlyOnInterrupt()
            throws InterruptedException {
        SignatureScanner scanner = SignatureScanner.newInstance();
        AtomicReference<Throwable> thrown = new AtomicReference<>();
        Thread worker = new Thread(() -> {
            try {
                scanner.findAllEPFalseMatches(randomFile);
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
