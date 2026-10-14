package io.github.struppigel.tools.anomalies;

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.sections.clr.CLRTableKey;
import io.github.struppigel.parser.sections.clr.CLRTableType;
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

/** ECMA-335 II.22: the [ERROR] rules of the metadata tables that a scanner can check on the tables alone. */
public class ClrTableAnomalyTest {

    private static final File HELLO = new File(TestreportsReader.RESOURCE_DIR + "/testfiles/HelloWorld.exe");
    private static final AnomalySubType[] SUBTYPES = {CLR_MODULE_ROW_COUNT, CLR_MULTIPLE_ASSEMBLY_ROWS, CLR_EMPTY_NAME,
            CLR_NULL_MVID, CLR_MODULE_RESERVED_SET, CLR_DUPLICATE_TYPEDEF, CLR_INHERITANCE_LOOP,
            CLR_INVALID_LIST_INDEX, CLR_INVALID_EXTENDS, CLR_INVALID_METHOD_FLAGS, CLR_DUPLICATE_METHOD};

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
        assertEquals(CLR_MODULE_ROW_COUNT.getSuperType(), AnomalyType.STRUCTURE);
        assertEquals(CLR_MULTIPLE_ASSEMBLY_ROWS.getSuperType(), AnomalyType.STRUCTURE);
        assertEquals(CLR_EMPTY_NAME.getSuperType(), AnomalyType.WRONG);
        assertEquals(CLR_NULL_MVID.getSuperType(), AnomalyType.WRONG);
        assertEquals(CLR_MODULE_RESERVED_SET.getSuperType(), AnomalyType.RESERVED);
        assertEquals(CLR_DUPLICATE_TYPEDEF.getSuperType(), AnomalyType.STRUCTURE);
        assertEquals(CLR_INHERITANCE_LOOP.getSuperType(), AnomalyType.STRUCTURE);
        assertEquals(CLR_INVALID_LIST_INDEX.getSuperType(), AnomalyType.WRONG);
        assertEquals(CLR_INVALID_EXTENDS.getSuperType(), AnomalyType.WRONG);
        assertEquals(CLR_INVALID_METHOD_FLAGS.getSuperType(), AnomalyType.WRONG);
        assertEquals(CLR_DUPLICATE_METHOD.getSuperType(), AnomalyType.STRUCTURE);
    }

    @Test
    public void unmodifiedFileHasNoneOfThem() throws IOException {
        PEData pe = mutate(b -> { });
        for (AnomalySubType subtype : SUBTYPES) {
            assertHasNotAnomalySubType(pe, subtype);
        }
    }

    @Test
    public void moduleTableWithoutExactlyOneRowIsStructural() throws IOException {
        assertHasAnomalySubType(mutate(b -> putLe(b, m.rowCountField(0x00), 2, 4)), CLR_MODULE_ROW_COUNT);
        assertHasAnomalySubType(mutate(b -> putLe(b, m.rowCountField(0x00), 0, 4)), CLR_MODULE_ROW_COUNT);
    }

    @Test
    public void moreThanOneAssemblyRowIsStructural() throws IOException {
        assertHasAnomalySubType(mutate(b -> putLe(b, m.rowCountField(0x20), 2, 4)), CLR_MULTIPLE_ASSEMBLY_ROWS);
    }

    @Test
    public void emptyNamesAreWrong() throws IOException {
        assertHasAnomalySubType(mutate(b -> m.setTableField(b, CLRTableType.MODULE, 1, CLRTableKey.MODULE_NAME, 0)),
                CLR_EMPTY_NAME);
        assertHasAnomalySubType(mutate(b -> m.setTableField(b, CLRTableType.ASSEMBLY, 1, CLRTableKey.ASSEMBLY_NAME, 0)),
                CLR_EMPTY_NAME);
        assertHasAnomalySubType(mutate(b -> m.setTableField(b, CLRTableType.TYPEDEF, 2, CLRTableKey.TYPEDEF_TYPE_NAME, 0)),
                CLR_EMPTY_NAME);
        assertHasAnomalySubType(mutate(b -> m.setTableField(b, CLRTableType.METHODDEF, 1, CLRTableKey.METHOD_NAME, 0)),
                CLR_EMPTY_NAME);
    }

    @Test
    public void nullNamespaceIsNotReported() throws IOException {
        PEData pe = mutate(b -> m.setTableField(b, CLRTableType.TYPEDEF, 2, CLRTableKey.TYPEDEF_TYPE_NAMESPACE, 0));
        assertHasNotAnomalySubType(pe, CLR_EMPTY_NAME);
    }

    @Test
    public void namespaceThatIsNotNullButEmptyIsWrong() throws IOException {
        // the index behind "<Module>" (8 characters) is its zero terminator, an empty entry
        PEData pe = mutate(b -> {
            long moduleName = m.tableField(CLRTableType.TYPEDEF, 1, CLRTableKey.TYPEDEF_TYPE_NAME).getValue();
            m.setTableField(b, CLRTableType.TYPEDEF, 2, CLRTableKey.TYPEDEF_TYPE_NAMESPACE, moduleName + 8);
        });
        assertHasAnomalySubType(pe, CLR_EMPTY_NAME);
    }

    @Test
    public void nullMvidIsWrong() throws IOException {
        assertHasAnomalySubType(mutate(b -> m.setTableField(b, CLRTableType.MODULE, 1, CLRTableKey.MODULE_MVID, 0)),
                CLR_NULL_MVID);
    }

    @Test
    public void reservedModuleColumnsAreReserved() throws IOException {
        assertHasAnomalySubType(mutate(b -> m.setTableField(b, CLRTableType.MODULE, 1, CLRTableKey.MODULE_GENERATION, 1)),
                CLR_MODULE_RESERVED_SET);
        assertHasAnomalySubType(mutate(b -> m.setTableField(b, CLRTableType.MODULE, 1, CLRTableKey.MODULE_ENCID, 1)),
                CLR_MODULE_RESERVED_SET);
        assertHasAnomalySubType(mutate(b -> m.setTableField(b, CLRTableType.MODULE, 1, CLRTableKey.MODULE_ENCBASEID, 1)),
                CLR_MODULE_RESERVED_SET);
    }

    @Test
    public void duplicateTypeDefIsStructural() throws IOException {
        // row 2 gets the name and namespace of row 1, both are no nested types
        PEData pe = mutate(b -> {
            long name = m.tableField(CLRTableType.TYPEDEF, 1, CLRTableKey.TYPEDEF_TYPE_NAME).getValue();
            long namespace = m.tableField(CLRTableType.TYPEDEF, 1, CLRTableKey.TYPEDEF_TYPE_NAMESPACE).getValue();
            m.setTableField(b, CLRTableType.TYPEDEF, 2, CLRTableKey.TYPEDEF_TYPE_NAME, name);
            m.setTableField(b, CLRTableType.TYPEDEF, 2, CLRTableKey.TYPEDEF_TYPE_NAMESPACE, namespace);
        });
        assertHasAnomalySubType(pe, CLR_DUPLICATE_TYPEDEF);
    }

    @Test
    public void nestedTypesAreNotComparedWithoutTheirOwner() throws IOException {
        // NestedPublic (2) in the visibility bits of row 2, the duplicate rule then needs the owner as well
        PEData pe = mutate(b -> {
            long name = m.tableField(CLRTableType.TYPEDEF, 1, CLRTableKey.TYPEDEF_TYPE_NAME).getValue();
            long namespace = m.tableField(CLRTableType.TYPEDEF, 1, CLRTableKey.TYPEDEF_TYPE_NAMESPACE).getValue();
            long flags = m.tableField(CLRTableType.TYPEDEF, 2, CLRTableKey.TYPEDEF_FLAGS).getValue();
            m.setTableField(b, CLRTableType.TYPEDEF, 2, CLRTableKey.TYPEDEF_TYPE_NAME, name);
            m.setTableField(b, CLRTableType.TYPEDEF, 2, CLRTableKey.TYPEDEF_TYPE_NAMESPACE, namespace);
            m.setTableField(b, CLRTableType.TYPEDEF, 2, CLRTableKey.TYPEDEF_FLAGS, (flags & ~7L) | 2);
        });
        assertHasNotAnomalySubType(pe, CLR_DUPLICATE_TYPEDEF);
    }

    @Test
    public void typeThatExtendsItselfIsALoop() throws IOException {
        // TypeDefOrRef: tag 0 is TypeDef, row 2 is the value 2 << 2
        PEData pe = mutate(b -> m.setTableField(b, CLRTableType.TYPEDEF, 2, CLRTableKey.TYPEDEF_EXTENDS, 2 << 2));
        assertHasAnomalySubType(pe, CLR_INHERITANCE_LOOP);
    }

    @Test
    public void inheritanceChainWithoutLoopIsNotReported() throws IOException {
        // row 2 extends row 1
        PEData pe = mutate(b -> m.setTableField(b, CLRTableType.TYPEDEF, 2, CLRTableKey.TYPEDEF_EXTENDS, 1 << 2));
        assertHasNotAnomalySubType(pe, CLR_INHERITANCE_LOOP);
    }

    @Test
    public void fieldAndMethodListBeyondTheTableAreWrong() throws IOException {
        // valid is 1 up to the row count + 1
        int methods = m.rowCount(CLRTableType.METHODDEF);
        int fields = m.rowCount(CLRTableType.FIELD);
        assertHasNotAnomalySubType(mutate(b -> m.setTableField(b, CLRTableType.TYPEDEF, 2,
                CLRTableKey.TYPEDEF_METHODLIST, methods + 1)), CLR_INVALID_LIST_INDEX);
        assertHasAnomalySubType(mutate(b -> m.setTableField(b, CLRTableType.TYPEDEF, 2,
                CLRTableKey.TYPEDEF_METHODLIST, methods + 2)), CLR_INVALID_LIST_INDEX);
        assertHasAnomalySubType(mutate(b -> m.setTableField(b, CLRTableType.TYPEDEF, 2,
                CLRTableKey.TYPEDEF_FIELDLIST, fields + 2)), CLR_INVALID_LIST_INDEX);
    }

    @Test
    public void classWithoutBaseClassIsWrong() throws IOException {
        // row 2 is a class, only <Module> and System.Object may have a null Extends
        PEData pe = mutate(b -> m.setTableField(b, CLRTableType.TYPEDEF, 2, CLRTableKey.TYPEDEF_EXTENDS, 0));
        assertHasAnomalySubType(pe, CLR_INVALID_EXTENDS);
    }

    @Test
    public void interfaceWithBaseClassIsWrong() throws IOException {
        // Interface (0x20) and Abstract (0x80) set, Extends stays non-null
        PEData pe = mutate(b -> {
            long flags = m.tableField(CLRTableType.TYPEDEF, 2, CLRTableKey.TYPEDEF_FLAGS).getValue();
            m.setTableField(b, CLRTableType.TYPEDEF, 2, CLRTableKey.TYPEDEF_FLAGS, flags | 0x20 | 0x80);
        });
        assertHasAnomalySubType(pe, CLR_INVALID_EXTENDS);
    }

    @Test
    public void extendsBehindTheLastRowIsWrong() throws IOException {
        // TypeDefOrRef tag 1 is TypeRef
        PEData pe = mutate(b -> m.setTableField(b, CLRTableType.TYPEDEF, 2, CLRTableKey.TYPEDEF_EXTENDS, (999 << 2) | 1));
        assertHasAnomalySubType(pe, CLR_INVALID_EXTENDS);
    }

    private PEData withMethodFlags(long flags) throws IOException {
        return mutate(b -> m.setTableField(b, CLRTableType.METHODDEF, 1, CLRTableKey.METHOD_FLAGS, flags));
    }

    @Test
    public void invalidCombinationsOfMethodFlagsAreWrong() throws IOException {
        long publicAccess = 0x6;
        long[] invalid = {
                publicAccess | 0x10 | 0x20,            // Static, Final
                publicAccess | 0x10 | 0x40,            // Static, Virtual
                publicAccess | 0x10 | 0x100 | 0x40,    // Static, NewSlot
                publicAccess | 0x20 | 0x400 | 0x40,    // Final, Abstract
                publicAccess | 0x400 | 0x2000 | 0x40,  // Abstract, PInvokeImpl
                0x0 | 0x800,                           // CompilerControlled, SpecialName
                0x0 | 0x1000 | 0x800,                  // CompilerControlled, RTSpecialName
                publicAccess | 0x400,                  // Abstract without Virtual
                publicAccess | 0x1000,                 // RTSpecialName without SpecialName
                publicAccess | 0x20,                   // Final without Virtual
                publicAccess | 0x100,                  // NewSlot without Virtual
                publicAccess | 0x200,                  // Strict without Virtual
                publicAccess | 0x2000 | 0x40,          // PInvokeImpl with Virtual
                0x7                                    // no valid member access
        };
        for (long flags : invalid) {
            assertHasAnomalySubType(withMethodFlags(flags), CLR_INVALID_METHOD_FLAGS);
        }
    }

    @Test
    public void usualMethodFlagsAreNotReported() throws IOException {
        long[] valid = {0x6 | 0x10 | 0x80, 0x6 | 0x40 | 0x80 | 0x100, 0x6 | 0x40 | 0x400 | 0x80, 0x6 | 0x80 | 0x800 | 0x1000,
                0x1 | 0x10, 0x6 | 0x40 | 0x20 | 0x80};
        for (long flags : valid) {
            assertHasNotAnomalySubType(withMethodFlags(flags), CLR_INVALID_METHOD_FLAGS);
        }
    }

    @Test
    public void duplicateMethodOfTheSameTypeIsStructural() throws IOException {
        // both methods are in TypeDef row 2, the second gets name and signature of the first
        PEData pe = mutate(b -> {
            long name = m.tableField(CLRTableType.METHODDEF, 1, CLRTableKey.METHOD_NAME).getValue();
            long signature = m.tableField(CLRTableType.METHODDEF, 1, CLRTableKey.METHOD_SIGNATURE).getValue();
            m.setTableField(b, CLRTableType.METHODDEF, 2, CLRTableKey.METHOD_NAME, name);
            m.setTableField(b, CLRTableType.METHODDEF, 2, CLRTableKey.METHOD_SIGNATURE, signature);
        });
        assertHasAnomalySubType(pe, CLR_DUPLICATE_METHOD);
    }
}
