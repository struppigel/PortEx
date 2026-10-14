package io.github.struppigel.tools.anomalies;

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.sections.clr.ClrMutator;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;

import static io.github.struppigel.parser.sections.clr.ClrMutator.putLe;
import static io.github.struppigel.tools.anomalies.AnomalySubType.*;
import static io.github.struppigel.tools.anomalies.PEAnomalyScannerTest.assertHasAnomalySubType;
import static io.github.struppigel.tools.anomalies.PEAnomalyScannerTest.assertHasNotAnomalySubType;
import static org.testng.Assert.assertEquals;

/** ECMA-335 II.25.3.1: a pure .NET image imports _CorExeMain or _CorDllMain from mscoree.dll and nothing else. */
public class ClrImportAnomalyTest {

    private static final File HELLO = new File(TestreportsReader.RESOURCE_DIR + "/testfiles/HelloWorld.exe");

    private ClrMutator m;

    @BeforeClass
    public void prepare() throws IOException {
        m = new ClrMutator(HELLO);
    }

    @AfterClass(alwaysRun = true)
    public void cleanup() throws IOException {
        m.delete();
    }

    private PEData mutate(Consumer<byte[]> mutation) throws IOException {
        return m.mutate(mutation);
    }

    private static void write(byte[] b, long offset, String ascii) {
        byte[] text = ascii.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(text, 0, b, (int) offset, text.length);
    }

    @Test
    public void typesOfTheSubtypes() {
        assertEquals(CLR_MULTIPLE_IMPORT_DESCRIPTORS.getSuperType(), AnomalyType.STRUCTURE);
        assertEquals(CLR_INVALID_IMPORT_DLL.getSuperType(), AnomalyType.WRONG);
        assertEquals(CLR_INVALID_IMPORT_SYMBOL.getSuperType(), AnomalyType.WRONG);
        assertEquals(CLR_NONZERO_IMPORT_HINT.getSuperType(), AnomalyType.WRONG);
    }

    @Test
    public void unmodifiedFileHasNoneOfThem() throws IOException {
        PEData pe = mutate(b -> { });
        for (AnomalySubType subtype : new AnomalySubType[]{CLR_MULTIPLE_IMPORT_DESCRIPTORS, CLR_INVALID_IMPORT_DLL,
                CLR_INVALID_IMPORT_SYMBOL, CLR_NONZERO_IMPORT_HINT}) {
            assertHasNotAnomalySubType(pe, subtype);
        }
    }

    @Test
    public void otherDllNameIsWrong() throws IOException {
        PEData pe = mutate(b -> write(b, m.indexOf("mscoree.dll"), "mscorex.dll"));
        assertHasAnomalySubType(pe, CLR_INVALID_IMPORT_DLL);
    }

    @Test
    public void upperCaseDllNameIsNotReported() throws IOException {
        // Windows file names are not case sensitive
        PEData pe = mutate(b -> write(b, m.indexOf("mscoree.dll"), "MSCOREE.DLL"));
        assertHasNotAnomalySubType(pe, CLR_INVALID_IMPORT_DLL);
    }

    @Test
    public void entryOfAnotherKindOfFileIsWrong() throws IOException {
        // HelloWorld.exe is no DLL, it has to import _CorExeMain
        PEData pe = mutate(b -> write(b, m.indexOf("_CorExeMain"), "_CorDllMain"));
        assertHasAnomalySubType(pe, CLR_INVALID_IMPORT_SYMBOL);
    }

    @Test
    public void symbolNameIsCaseSensitive() throws IOException {
        PEData pe = mutate(b -> write(b, m.indexOf("_CorExeMain"), "_corexemain"));
        assertHasAnomalySubType(pe, CLR_INVALID_IMPORT_SYMBOL);
    }

    @Test
    public void hintThatIsNotZeroIsWrong() throws IOException {
        PEData pe = mutate(b -> putLe(b, m.indexOf("_CorExeMain") - 2, 1, 2));
        assertHasAnomalySubType(pe, CLR_NONZERO_IMPORT_HINT);
        assertHasNotAnomalySubType(pe, CLR_INVALID_IMPORT_SYMBOL);
    }

    @Test
    public void secondImportDescriptorIsStructural() throws IOException {
        long table = m.dataDirectoryTarget(1);
        PEData pe = mutate(b -> System.arraycopy(b, (int) table, b, (int) table + 20, 20));
        assertHasAnomalySubType(pe, CLR_MULTIPLE_IMPORT_DESCRIPTORS);
    }
}
