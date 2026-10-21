package io.github.struppigel.parser.sections.edata;

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.PELoaderTest;
import io.github.struppigel.parser.PhysicalLocation;
import io.github.struppigel.parser.optheader.WindowsEntryKey;
import io.github.struppigel.parser.sections.SectionLoader;
import java.util.Optional;
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
    public void physicalLocationsCoverTheWholeExportNames() throws IOException {
        for (String file : new String[]{"corkami/ownexports2.exe", "corkami/exports_order.exe", "corkami/dllfw.dll"}) {
            PEData data = PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR + "/" + file));
            SectionLoader loader = new SectionLoader(data);
            ExportSection edata = loader.loadExportSection();
            List<PhysicalLocation> locations = edata.getPhysicalLocations();
            int longNames = 0;
            for (Entry<?, String> name : edata.getPointerNameMap().entrySet()) {
                // a Scala map of Long keys, which Java sees as Object
                long start = loader.getFileOffset(((Number) name.getKey()).longValue());
                // the characters and the zero terminator
                for (long position = start; position <= start + name.getValue().length(); position++) {
                    final long p = position;
                    assertTrue(locations.stream().anyMatch(l -> l.from() <= p && p < l.from() + l.size()),
                            file + " " + name.getValue() + " byte " + (p - start));
                }
                longNames += name.getValue().length() >= 4 ? 1 : 0;
            }
            assertTrue(longNames > 0, file + " has no name with 4 or more characters");
        }
    }

    @Test
    public void physicalLocationsCoverTheNameOfTheDll() throws IOException {
        PEData data = PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR + "/CVE_2013_3900/CVE_2013_3900"));
        SectionLoader loader = new SectionLoader(data);
        ExportSection edata = loader.loadExportSection();
        long start = loader.getFileOffset(edata.getExportDirectory().get(ExportDirectoryKey.NAME_RVA));

        assertEquals(edata.getDllName(), "winfw.dll");
        PhysicalLocation name = edata.maybeGetDllNameLocation().get();
        assertEquals(name.from(), start);
        assertEquals(name.size(), "winfw.dll".length() + 1, "the name and its zero terminator");
        List<PhysicalLocation> locations = edata.getPhysicalLocations();
        for (long position = start; position < start + name.size(); position++) {
            final long p = position;
            assertTrue(locations.stream().anyMatch(l -> l.from() <= p && p < l.from() + l.size()),
                    "byte " + (p - start) + " of the name");
        }
    }

    @Test
    public void physicalLocationsCoverTheForwarderStrings() throws IOException {
        // exports_doc.exe has an empty forwarder string
        for (String file : new String[]{"corkami/dllfw.dll", "corkami/dllfwloop.dll", "corkami/exports_doc.exe",
                "Haus/win_test.dll"}) {
            PEData data = PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR + "/" + file));
            SectionLoader loader = new SectionLoader(data);
            ExportSection edata = loader.loadExportSection();
            List<PhysicalLocation> locations = edata.getPhysicalLocations();
            int forwarders = 0;
            for (ExportEntry entry : edata.getExportEntries()) {
                Optional<PhysicalLocation> location = edata.maybeGetForwarderLocation(entry);
                assertEquals(location.isPresent(), entry.forwarded(), file + " " + entry);
                if (!location.isPresent()) {
                    continue;
                }
                forwarders++;
                String forwarder = entry.maybeGetForwarder().get();
                long start = loader.getFileOffset(entry.symbolRVA());
                assertEquals(location.get().from(), start, file + " " + forwarder);
                assertEquals(location.get().size(), forwarder.length() + 1L, file + " " + forwarder);
                for (long position = start; position < start + location.get().size(); position++) {
                    final long p = position;
                    assertTrue(locations.stream().anyMatch(l -> l.from() <= p && p < l.from() + l.size()),
                            file + " " + forwarder + " byte " + (p - start));
                }
            }
            assertTrue(forwarders > 0, file + " has forwarded exports");
        }
    }

    @Test
    public void physicalLocationsAreOrderedAndMerged() throws IOException {
        // the forwarder strings are between the export names
        PEData data = PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR + "/Haus/win_test.dll"));
        List<PhysicalLocation> locations = new SectionLoader(data).loadExportSection().getPhysicalLocations();
        for (int i = 1; i < locations.size(); i++) {
            PhysicalLocation previous = locations.get(i - 1);
            assertTrue(previous.from() + previous.size() < locations.get(i).from(), previous + " before "
                    + locations.get(i));
        }
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
