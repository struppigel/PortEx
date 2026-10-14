package io.github.struppigel.tools.anomalies;

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.sections.clr.CLIHeaderKey;
import io.github.struppigel.parser.sections.clr.ClrMutator;
import io.github.struppigel.parser.sections.clr.MetadataRootKey;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.util.function.Consumer;

import static io.github.struppigel.parser.sections.clr.ClrMutator.getLe;
import static io.github.struppigel.parser.sections.clr.ClrMutator.putLe;
import static io.github.struppigel.tools.anomalies.AnomalySubType.*;
import static io.github.struppigel.tools.anomalies.PEAnomalyScannerTest.assertHasAnomalySubType;
import static io.github.struppigel.tools.anomalies.PEAnomalyScannerTest.assertHasNotAnomalySubType;

/** One-property mutations of HelloWorld.exe, each must be reported with the subtype of the changed field. */
public class ClrHeaderAnomalyTest {

    private static final File HELLO = new File(TestreportsReader.RESOURCE_DIR + "/testfiles/HelloWorld.exe");
    private static final AnomalySubType[] SUBTYPES = {
            CLR_TOO_SMALL_HEADER_SIZE, CLR_UNUSUAL_HEADER_SIZE, CLR_INVALID_RUNTIME_MAJOR_VERSION,
            CLR_UNUSUAL_RUNTIME_MINOR_VERSION, CLR_UNUSUAL_ILONLY_CLEARED, CLR_UNUSUAL_NATIVE_ENTRYPOINT,
            CLR_TRACKDEBUGDATA_SET, CLR_UNDEFINED_FLAGS, CLR_NONZERO_HEADER_FIELD,
            METADATA_ROOT_INVALID_VERSION, METADATA_ROOT_RESERVED_SET,
            TABLES_STREAM_INVALID_VERSION, TABLES_STREAM_RESERVED_SET, TABLES_STREAM_UNDEFINED_HEAP_SIZES,
            TABLES_STREAM_NON_EXISTENT_TABLES, CLR_UNUSUAL_DATA_DIR, CLR_UNEXPECTED_DATA_DIR, CLR_HEADER_IN_WRITEABLE_SECTION};

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

    private long cli(CLIHeaderKey key) {
        return m.cliHeaderField(key);
    }

    private long root(MetadataRootKey key) {
        return m.metadataRootField(key);
    }

    @Test
    public void unmodifiedFileHasNoneOfThem() throws IOException {
        PEData pe = mutate(b -> { });
        for (AnomalySubType subtype : SUBTYPES) {
            assertHasNotAnomalySubType(pe, subtype);
        }
    }

    @Test
    public void headerSizeBelowTheSpecifiedHeaderIsWrong() throws IOException {
        PEData pe = mutate(b -> putLe(b, cli(CLIHeaderKey.CB), 0x40, 4));
        assertHasAnomalySubType(pe, CLR_TOO_SMALL_HEADER_SIZE);
        assertHasNotAnomalySubType(pe, CLR_UNUSUAL_HEADER_SIZE);
    }

    @Test
    public void headerSizeAboveTheSpecifiedHeaderIsNonDefault() throws IOException {
        PEData pe = mutate(b -> putLe(b, cli(CLIHeaderKey.CB), 0x50, 4));
        assertHasAnomalySubType(pe, CLR_UNUSUAL_HEADER_SIZE);
        assertHasNotAnomalySubType(pe, CLR_TOO_SMALL_HEADER_SIZE);
    }

    @Test
    public void runtimeMajorVersionNotTwoIsWrong() throws IOException {
        assertHasAnomalySubType(mutate(b -> putLe(b, cli(CLIHeaderKey.MAJOR_RUNTIME_VERSION), 3, 2)),
                CLR_INVALID_RUNTIME_MAJOR_VERSION);
        assertHasAnomalySubType(mutate(b -> putLe(b, cli(CLIHeaderKey.MAJOR_RUNTIME_VERSION), 0, 2)),
                CLR_INVALID_RUNTIME_MAJOR_VERSION);
    }

    @Test
    public void runtimeMinorVersionOtherThanZeroOrFiveIsNonDefault() throws IOException {
        // 2.5 is what the Microsoft compilers write, the specification says currently 0
        assertHasAnomalySubType(mutate(b -> putLe(b, cli(CLIHeaderKey.MINOR_RUNTIME_VERSION), 9, 2)),
                CLR_UNUSUAL_RUNTIME_MINOR_VERSION);
        for (long minor : new long[]{0, 5}) {
            assertHasNotAnomalySubType(mutate(b -> putLe(b, cli(CLIHeaderKey.MINOR_RUNTIME_VERSION), minor, 2)),
                    CLR_UNUSUAL_RUNTIME_MINOR_VERSION);
        }
    }

    @Test
    public void clearedIlOnlyFlagIsNonDefault() throws IOException {
        PEData pe = mutate(b -> putLe(b, cli(CLIHeaderKey.FLAGS), getLe(b, cli(CLIHeaderKey.FLAGS), 4) & ~0x1L, 4));
        assertHasAnomalySubType(pe, CLR_UNUSUAL_ILONLY_CLEARED);
    }

    @Test
    public void nativeEntryPointFlagIsNonDefault() throws IOException {
        PEData pe = mutate(b -> putLe(b, cli(CLIHeaderKey.FLAGS), getLe(b, cli(CLIHeaderKey.FLAGS), 4) | 0x10, 4));
        assertHasAnomalySubType(pe, CLR_UNUSUAL_NATIVE_ENTRYPOINT);
    }

    @Test
    public void trackDebugDataFlagIsReserved() throws IOException {
        PEData pe = mutate(b -> putLe(b, cli(CLIHeaderKey.FLAGS), getLe(b, cli(CLIHeaderKey.FLAGS), 4) | 0x10000, 4));
        assertHasAnomalySubType(pe, CLR_TRACKDEBUGDATA_SET);
        assertHasNotAnomalySubType(pe, CLR_UNDEFINED_FLAGS);
    }

    @Test
    public void undefinedFlagBitsAreReserved() throws IOException {
        for (long bit : new long[]{0x20, 0x100, 0x8000, 0x40000, 0x80000000L}) {
            PEData pe = mutate(b -> putLe(b, cli(CLIHeaderKey.FLAGS), getLe(b, cli(CLIHeaderKey.FLAGS), 4) | bit, 4));
            assertHasAnomalySubType(pe, CLR_UNDEFINED_FLAGS);
        }
    }

    @Test
    public void definedFlagBitsAreNotUndefined() throws IOException {
        // 32BITREQUIRED, IL_LIBRARY, STRONGNAMESIGNED, 32BITPREFERRED
        for (long bit : new long[]{0x2, 0x4, 0x8, 0x20000}) {
            PEData pe = mutate(b -> putLe(b, cli(CLIHeaderKey.FLAGS), getLe(b, cli(CLIHeaderKey.FLAGS), 4) | bit, 4));
            assertHasNotAnomalySubType(pe, CLR_UNDEFINED_FLAGS);
        }
    }

    @Test
    public void fieldsThatAreAlwaysZeroAreWrongWhenSet() throws IOException {
        for (CLIHeaderKey key : new CLIHeaderKey[]{CLIHeaderKey.CODE_MANAGER_TABLE,
                CLIHeaderKey.EXPORT_ADDRESS_TABLE_JUMPS}) {
            assertHasAnomalySubType(mutate(b -> putLe(b, cli(key), 0x2000, 4)), CLR_NONZERO_HEADER_FIELD);
            assertHasAnomalySubType(mutate(b -> putLe(b, cli(key) + 4, 8, 4)), CLR_NONZERO_HEADER_FIELD);
        }
    }

    @Test
    public void managedNativeHeaderIsNotReported() throws IOException {
        // ReadyToRun images set it, the check is held back until it can tell them apart
        PEData pe = mutate(b -> putLe(b, cli(CLIHeaderKey.MANAGED_NATIVE_HEADER), 0x2000, 4));
        assertHasNotAnomalySubType(pe, CLR_NONZERO_HEADER_FIELD);
    }

    @Test
    public void dataDirectoriesSpecifiedAsZeroAreReportedByTheirTypicalUse() throws IOException {
        // export, exception, TLS and load config occur in a few shipped assemblies (mixed mode, x64)
        for (int index : new int[]{0, 3, 9, 10}) {
            assertHasAnomalySubType(mutate(b -> setDataDir(b, index)), CLR_UNUSUAL_DATA_DIR);
            assertHasNotAnomalySubType(mutate(b -> setDataDir(b, index)), CLR_UNEXPECTED_DATA_DIR);
        }
        // bound import and delay import were not found in any of 721 shipped assemblies
        for (int index : new int[]{11, 13}) {
            assertHasAnomalySubType(mutate(b -> setDataDir(b, index)), CLR_UNEXPECTED_DATA_DIR);
            assertHasNotAnomalySubType(mutate(b -> setDataDir(b, index)), CLR_UNUSUAL_DATA_DIR);
        }
    }

    @Test
    public void resourceCertificateAndDebugDirectoriesAreNotReported() throws IOException {
        // present in 721, 719 and 512 of 721 shipped assemblies
        for (int index : new int[]{2, 4, 6}) {
            PEData pe = mutate(b -> setDataDir(b, index));
            assertHasNotAnomalySubType(pe, CLR_UNUSUAL_DATA_DIR);
            assertHasNotAnomalySubType(pe, CLR_UNEXPECTED_DATA_DIR);
        }
    }

    private void setDataDir(byte[] b, int index) {
        long entry = m.dataDirectoryEntry(index);
        putLe(b, entry, 0x2000, 4);
        putLe(b, entry + 4, 8, 4);
    }

    @Test
    public void cliHeaderInAWriteableSectionIsStructural() throws IOException {
        long field = m.cliHeaderSectionCharacteristics();
        assertHasAnomalySubType(mutate(b -> putLe(b, field, getLe(b, field, 4) | 0x80000000L, 4)),
                CLR_HEADER_IN_WRITEABLE_SECTION);
        assertHasNotAnomalySubType(mutate(b -> putLe(b, field, getLe(b, field, 4) & ~0x80000000L, 4)),
                CLR_HEADER_IN_WRITEABLE_SECTION);
    }

    @Test
    public void metadataRootVersionNotOneDotOneIsWrong() throws IOException {
        assertHasAnomalySubType(mutate(b -> putLe(b, root(MetadataRootKey.MAJOR_VERSION), 2, 2)),
                METADATA_ROOT_INVALID_VERSION);
        assertHasAnomalySubType(mutate(b -> putLe(b, root(MetadataRootKey.MINOR_VERSION), 5, 2)),
                METADATA_ROOT_INVALID_VERSION);
    }

    @Test
    public void metadataRootReservedFieldsAreReserved() throws IOException {
        assertHasAnomalySubType(mutate(b -> putLe(b, root(MetadataRootKey.RESERVED), 1, 4)),
                METADATA_ROOT_RESERVED_SET);
        assertHasAnomalySubType(mutate(b -> putLe(b, root(MetadataRootKey.FLAGS), 1, 2)),
                METADATA_ROOT_RESERVED_SET);
    }

    @Test
    public void tablesStreamVersionNotTwoDotZeroIsWrong() throws IOException {
        assertHasAnomalySubType(mutate(b -> b[(int) m.tablesStream() + 4] = 3), TABLES_STREAM_INVALID_VERSION);
        assertHasAnomalySubType(mutate(b -> b[(int) m.tablesStream() + 5] = 1), TABLES_STREAM_INVALID_VERSION);
    }

    @Test
    public void tablesStreamReservedFieldsAreReserved() throws IOException {
        assertHasAnomalySubType(mutate(b -> putLe(b, m.tablesStream(), 1, 4)), TABLES_STREAM_RESERVED_SET);
        assertHasAnomalySubType(mutate(b -> b[(int) m.tablesStream() + 7] = 0), TABLES_STREAM_RESERVED_SET);
    }

    @Test
    public void undefinedHeapSizesBitsAreReserved() throws IOException {
        for (int bit : new int[]{0x08, 0x10, 0x20, 0x40, 0x80}) {
            assertHasAnomalySubType(mutate(b -> b[(int) m.tablesStream() + 6] |= (byte) bit),
                    TABLES_STREAM_UNDEFINED_HEAP_SIZES);
        }
    }

    @Test
    public void validBitsAboveTheLastTableAreWrong() throws IOException {
        for (int bit : new int[]{0x2D, 0x30, 0x3F}) {
            PEData pe = mutate(b -> putLe(b, m.tablesStreamValid(), getLe(b, m.tablesStreamValid(), 8) | (1L << bit), 8));
            assertHasAnomalySubType(pe, TABLES_STREAM_NON_EXISTENT_TABLES);
        }
    }
}
