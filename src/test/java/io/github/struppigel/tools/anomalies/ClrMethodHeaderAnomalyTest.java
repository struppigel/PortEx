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

/** ECMA-335 II.25.4: the first byte of a method body tells whether it has a tiny or a fat header. */
public class ClrMethodHeaderAnomalyTest {

    private static final File HELLO = new File(TestreportsReader.RESOURCE_DIR + "/testfiles/HelloWorld.exe");

    private ClrMutator m;
    private long header;

    @BeforeClass
    public void prepare() throws IOException {
        m = new ClrMutator(HELLO);
        header = m.fileOffset(m.firstMethodRva());
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
        assertEquals(CLR_INVALID_METHOD_HEADER.getSuperType(), AnomalyType.WRONG);
        assertEquals(CLR_INVALID_FAT_HEADER_SIZE.getSuperType(), AnomalyType.WRONG);
        assertEquals(CLR_MISALIGNED_FAT_HEADER.getSuperType(), AnomalyType.WRONG);
    }

    @Test
    public void unmodifiedFileHasNoneOfThem() throws IOException {
        PEData pe = mutate(b -> { });
        assertHasNotAnomalySubType(pe, CLR_INVALID_METHOD_HEADER);
        assertHasNotAnomalySubType(pe, CLR_INVALID_FAT_HEADER_SIZE);
        assertHasNotAnomalySubType(pe, CLR_MISALIGNED_FAT_HEADER);
    }

    @Test
    public void headerTypeBitsThatAreNeitherTinyNorFatAreWrong() throws IOException {
        for (int bits : new int[]{0, 1}) {
            PEData pe = mutate(b -> b[(int) header] = (byte) ((b[(int) header] & ~3) | bits));
            assertHasAnomalySubType(pe, CLR_INVALID_METHOD_HEADER);
        }
    }

    @Test
    public void fatHeaderSizeNotThreeIsWrong() throws IOException {
        // flags 0x03 in the first byte, size 5 in the high nibble of the second byte
        PEData pe = mutate(b -> {
            b[(int) header] = 0x03;
            b[(int) header + 1] = 0x50;
        });
        assertHasAnomalySubType(pe, CLR_INVALID_FAT_HEADER_SIZE);
    }

    @Test
    public void fatHeaderSizeThreeIsNotReported() throws IOException {
        PEData pe = mutate(b -> {
            b[(int) header] = 0x03;
            b[(int) header + 1] = 0x30;
        });
        assertHasNotAnomalySubType(pe, CLR_INVALID_FAT_HEADER_SIZE);
    }

    @Test
    public void fatHeaderThatIsNotOnAFourByteBoundaryIsWrong() throws IOException {
        // the RVA is moved by one byte, there the first byte is set to the fat format with size 3
        PEData pe = mutate(b -> {
            putLe(b, m.firstMethodRvaField(), m.firstMethodRva() + 1, 4);
            b[(int) header + 1] = 0x03;
            b[(int) header + 2] = 0x30;
        });
        assertHasAnomalySubType(pe, CLR_MISALIGNED_FAT_HEADER);
    }

    @Test
    public void tinyHeaderOnAnyByteIsNotReported() throws IOException {
        PEData pe = mutate(b -> {
            putLe(b, m.firstMethodRvaField(), m.firstMethodRva() + 1, 4);
            b[(int) header + 1] = 0x0A;
        });
        assertHasNotAnomalySubType(pe, CLR_MISALIGNED_FAT_HEADER);
    }
}
