package io.github.struppigel.parser.sections.edata;

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.PELoaderTest;
import io.github.struppigel.parser.optheader.WindowsEntryKey;
import io.github.struppigel.parser.sections.SectionLoader;
import com.google.common.base.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Stream;

import static org.testng.Assert.*;

public class ExportSectionTest {

    @SuppressWarnings("unused")
    private static final Logger logger = LogManager
            .getLogger(ExportSectionTest.class.getName());
    private Map<File, List<ExportEntry>> exportEntries;
    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        exportEntries = TestreportsReader.readExportEntries();
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void forwarderTest() throws IOException {
        File forwarder = new File(TestreportsReader.RESOURCE_DIR
                + "/corkami/dllfw.dll");
        PEData data = PELoader.loadPE(forwarder);
        ExportSection edata = new SectionLoader(data).loadExportSection();
        List<ExportEntry> exportEntries = edata.getExportEntries();
        for (ExportEntry export : exportEntries) {
            assertTrue(export.forwarded());
            assertEquals(export.maybeGetForwarder().get(), "msvcrt.printf");
        }

        File nonforwarder = new File(TestreportsReader.RESOURCE_DIR
                + "/corkami/exports_order.exe");
        data = PELoader.loadPE(nonforwarder);
        edata = new SectionLoader(data).loadExportSection();
        exportEntries = edata.getExportEntries();
        for (ExportEntry export : exportEntries) {
            assertFalse(export.forwarded());
        }

    }

    @Test
    public void virtualAndNegativeExportTest() throws IOException {
        File forwarder = new File(TestreportsReader.RESOURCE_DIR
                + "/corkami/ownexports2.exe");
        PEData data = PELoader.loadPE(forwarder);
        ExportSection edata = new SectionLoader(data).loadExportSection();
        List<ExportEntry> exportEntries = edata.getExportEntries();
        assertEquals(exportEntries.size(), 2);
        assertHasExportByName(exportEntries, "offset -1");
        assertHasExportByName(exportEntries, "virtual");
        assertEquals(edata.getSymbolRVAForName("offset -1"), 0xFFFFFFFFL);
        assertEquals(edata.getSymbolRVAForName("virtual"), 0xFF8L);
    }

    private void assertHasExportByName(List<ExportEntry> exportEntries, String exportName) {
        Stream<ExportEntry> result = exportEntries.stream().filter(e -> e instanceof ExportNameEntry && ((ExportNameEntry) e).name().equals(exportName));
        assertTrue(result.count() > 0);
    }

    @Test
    public void forwarderLoopTest() throws IOException {
        File file = new File(TestreportsReader.RESOURCE_DIR
                + "/corkami/dllfwloop.dll");
        PEData data = PELoader.loadPE(file);
        ExportSection edata = new SectionLoader(data).loadExportSection();
        List<ExportEntry> exportEntries = edata.getExportEntries();
        assertEquals(exportEntries.size(), 6);
        assertEquals(edata.getOrdinalForName("ExitProcess"),0);
        assertEquals(edata.getOrdinalForName("LoopHere"),1);
        assertEquals(edata.getOrdinalForName("LoopOnceAgain"),2);
        assertEquals(edata.getOrdinalForName("GroundHogDay"),3);
        assertEquals(edata.getOrdinalForName("Ying"),4);
        assertEquals(edata.getOrdinalForName("Yang"),5);
        assertOrdinalHasForwarder(exportEntries, 0, "dllfwloop.LoopHere");
        assertOrdinalHasForwarder(exportEntries, 1, "dllfwloop.LoopOnceAgain");
        assertOrdinalHasForwarder(exportEntries, 2, "msvcrt.printf");
        assertOrdinalHasForwarder(exportEntries, 3, "dllfwloop.GroundHogDay");
        assertOrdinalHasForwarder(exportEntries, 4, "dllfwloop.Yang");
        assertOrdinalHasForwarder(exportEntries, 5, "dllfwloop.Ying");
    }
    private void assertOrdinalHasForwarder(List<ExportEntry> exportEntries, int ordinal, String forwarder) {
        for(ExportEntry e : exportEntries) {
            if(e.ordinal() == ordinal) {
                assertHasForwarder(e, forwarder);
                break;
            }
        }
    }

    private void assertHasForwarder(ExportEntry entry, String forwarder) {
        if(entry.maybeGetForwarder().isPresent()){
            assertEquals(entry.maybeGetForwarder().get(), forwarder);
        }
    }

    @Test
    public void emptyExportName() throws IOException {
        File file = new File(TestreportsReader.RESOURCE_DIR
                + "/corkami/dllemptyexp.dll");
        PEData data = PELoader.loadPE(file);
        List<ExportEntry> list = data.loadExports();
        assertEquals(list.size(), 1);
        ExportNameEntry entry = (ExportNameEntry) list.get(0);
        assertEquals(entry.name(), "");
    }

    @Test
    public void getExportEntries() throws IOException {
        // assertEquals(pedata.size(), exportEntries.size()); TODO
        for (Entry<File, List<ExportEntry>> set : exportEntries.entrySet()) {
            File file = set.getKey();
            List<ExportEntry> expected = set.getValue();
            String filename = file.getName().replace(".txt", "");
            PEData datum = pedata.get(filename);
            SectionLoader loader = new SectionLoader(datum);
            Optional<ExportSection> edata = loader.maybeLoadExportSection();
            if (!edata.isPresent()) {
                assertTrue(expected.size() == 0);
            } else {
                expected = substractImageBase(expected, datum);
                List<ExportEntry> actual = edata.get().getExportEntries();
                assertEquals(actual, expected);
            }

        }
    }

    // Patches the expected list to match our RVA that has not the image base
    // added
    private List<ExportEntry> substractImageBase(List<ExportEntry> expected,
            PEData datum) {
        List<ExportEntry> list = new ArrayList<ExportEntry>();
        long imageBase = datum.getOptionalHeader().getWindowsFieldEntry(
                WindowsEntryKey.IMAGE_BASE).getValue();
        for (ExportEntry entry : expected) {
            if (entry instanceof ExportNameEntry) {
                list.add(new ExportNameEntry(entry.symbolRVA() - imageBase,
                        ((ExportNameEntry) entry).name(), entry.ordinal()));
            } else {
                list.add(new ExportEntry(entry.symbolRVA() - imageBase, entry
                        .ordinal()));
            }
        }
        return list;
    }
}
