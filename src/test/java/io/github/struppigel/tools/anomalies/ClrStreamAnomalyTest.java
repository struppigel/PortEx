package io.github.struppigel.tools.anomalies;

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.sections.clr.ClrMutator;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.util.function.Consumer;

import static io.github.struppigel.parser.sections.clr.ClrMutator.putLe;
import static io.github.struppigel.tools.anomalies.AnomalySubType.*;
import static io.github.struppigel.tools.anomalies.PEAnomalyScannerTest.assertHasAnomalySubType;
import static io.github.struppigel.tools.anomalies.PEAnomalyScannerTest.assertHasNotAnomalySubType;
import static org.testng.Assert.assertEquals;

/** One-property mutations of the stream headers and heaps of HelloWorld.exe. */
public class ClrStreamAnomalyTest {

    private static final File HELLO = new File(TestreportsReader.RESOURCE_DIR + "/testfiles/HelloWorld.exe");
    private static final String[] STREAMS = {"#Strings", "#US", "#Blob", "#GUID"};

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

    @Test
    public void typesOfTheSubtypes() {
        assertEquals(CLR_STREAM_SIZE_NOT_ALIGNED.getSuperType(), AnomalyType.WRONG);
        assertEquals(CLR_UNUSUAL_STREAM_NAME.getSuperType(), AnomalyType.NON_DEFAULT);
        assertEquals(CLR_HEAP_FIRST_ENTRY_NOT_EMPTY.getSuperType(), AnomalyType.WRONG);
    }

    @Test
    public void unmodifiedFileHasNoneOfThem() throws IOException {
        PEData pe = mutate(b -> { });
        assertHasNotAnomalySubType(pe, CLR_STREAM_SIZE_NOT_ALIGNED);
        assertHasNotAnomalySubType(pe, CLR_UNUSUAL_STREAM_NAME);
        assertHasNotAnomalySubType(pe, CLR_HEAP_FIRST_ENTRY_NOT_EMPTY);
    }

    @Test
    public void streamSizeThatIsNotAMultipleOfFourIsWrong() throws IOException {
        for (String name : STREAMS) {
            long size = m.streamSize(name);
            PEData pe = mutate(b -> putLe(b, m.streamHeader(name) + 4, size - 1, 4));
            assertHasAnomalySubType(pe, CLR_STREAM_SIZE_NOT_ALIGNED);
        }
    }

    @Test
    public void unknownStreamNameIsNonDefault() throws IOException {
        // #GUID becomes #GUIX, the name field starts 8 bytes after the header start
        PEData pe = mutate(b -> b[(int) m.streamHeader("#GUID") + 8 + 4] = 'X');
        assertHasAnomalySubType(pe, CLR_UNUSUAL_STREAM_NAME);
    }

    @Test
    public void firstHeapEntryThatIsNotEmptyIsWrong() throws IOException {
        for (String name : new String[]{"#Strings", "#US", "#Blob"}) {
            PEData pe = mutate(b -> b[(int) m.streamStart(name)] = 0x41);
            assertHasAnomalySubType(pe, CLR_HEAP_FIRST_ENTRY_NOT_EMPTY);
        }
    }
}
