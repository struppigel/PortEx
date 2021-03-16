package com.github.katjahahn;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.parser.IOUtil;
import com.github.katjahahn.parser.PhysicalLocation;
import com.github.katjahahn.parser.StandardField;
import com.github.katjahahn.parser.coffheader.COFFHeaderKey;
import com.github.katjahahn.parser.msdos.MSDOSHeaderKey;
import com.github.katjahahn.parser.optheader.DataDirEntry;
import com.github.katjahahn.parser.optheader.DataDirectoryKey;
import com.github.katjahahn.parser.optheader.StandardFieldEntryKey;
import com.github.katjahahn.parser.optheader.WindowsEntryKey;
import com.github.katjahahn.parser.sections.SectionHeader;
import com.github.katjahahn.parser.sections.SectionHeaderKey;
import com.github.katjahahn.parser.sections.edata.ExportEntry;
import com.github.katjahahn.parser.sections.edata.ExportNameEntry;
import com.github.katjahahn.parser.sections.idata.ImportDLL;
import com.github.katjahahn.parser.sections.idata.NameImport;
import com.github.katjahahn.parser.sections.idata.OrdinalImport;
import com.github.katjahahn.parser.sections.rsrc.ResourceDataEntry;

public class TestreportsReader {

    private static final Logger logger = LogManager
            .getLogger(TestreportsReader.class.getName());
    public static final String NL = System.getProperty("line.separator");

    public static final String RESOURCE_DIR = "portextestfiles";
    public static final String TEST_FILE_DIR = "/testfiles";
    private static final String TEST_REPORTS_DIR = "/reports";
    private static final String EXPORT_REPORTS_DIR = "/exportreports";
    private static final String IMPORT_REPORTS_DIR = "/importreports";
    
    public static Map<File, List<ImportDLL>> readImportEntries()
            throws IOException {
        Map<File, List<ImportDLL>> data = new HashMap<>();
        File directory = Paths.get(RESOURCE_DIR, IMPORT_REPORTS_DIR).toFile();
        for (File file : directory.listFiles()) {
            if (!file.isDirectory()) {
                List<ImportDLL> entries = readImportEntries(file);
                data.put(file, entries);
            }
        }
        return data;
    }

    private static List<ImportDLL> readImportEntries(File file)
            throws IOException {
        List<String[]> entries = IOUtil.readArrayFrom(file);
        List<ImportDLL> list = new ArrayList<>();
        ImportDLL dll = null;
        for (String[] entry : entries) {
            if (entry.length == 1 || entry.length == 0) { // new ImportDLL
                if (dll != null) {
                    list.add(dll);
                }
                dll = new ImportDLL(entry[0]);
            } else if (entry.length == 4) { // ImportDLL entry
                if (dll == null) {
                    logger.error("parsing error for line: " + entry[0] + ";"
                            + entry[1]);
                } else {
                    Long rva = Long.parseLong(entry[0]);
                    String name = entry[1];
                    List<PhysicalLocation> empty = new ArrayList<>();
                    if (!entry[3].contains("None")) {
                        int ordinal = Integer.parseInt(entry[3]);
                        OrdinalImport ord = new OrdinalImport(ordinal, rva, 0L,
                                null, empty);
                        dll.add(ord);
                    } else {
                        int hint = Integer.parseInt(entry[2]);
                        NameImport nameImp = new NameImport(rva, 0L, name, hint,
                                -1, null, empty);
                        dll.add(nameImp);
                    }
                }
            }
        }
        if (dll != null) {
            list.add(dll);
        }
        return list;
    }

    public static Map<File, List<ExportEntry>> readExportEntries()
            throws IOException {
        Map<File, List<ExportEntry>> data = new HashMap<>();
        File directory = Paths.get(RESOURCE_DIR, EXPORT_REPORTS_DIR).toFile();
        for (File file : directory.listFiles()) {
            if (!file.isDirectory()) {
                List<ExportEntry> entries = readExportEntries(file);
                data.put(file, entries);
            }
        }
        return data;
    }

    private static List<ExportEntry> readExportEntries(File file)
            throws IOException {
        List<String[]> entries = IOUtil.readArrayFrom(file);
        List<ExportEntry> list = new ArrayList<>();
        for (String[] entry : entries) {
            Long rva = Long.parseLong(entry[0]);
            String name = entry[1];
            int ordinal = Integer.parseInt(entry[2]);
            if (name.equals("None")) {
                list.add(new ExportEntry(rva, ordinal));
            } else {
                list.add(new ExportNameEntry(rva, name, ordinal));
            }
        }
        return list;
    }

    /**
     * Parses all testfile reports (by pev) and creates TestData instances from
     * it.
     * 
     * @return list with all TestData instances
     * @throws IOException
     */
    public static List<TestData> readTestDataList() throws IOException {
        List<TestData> data = new LinkedList<>();
        File directory = Paths.get(RESOURCE_DIR, TEST_REPORTS_DIR).toFile();
        System.out.println("reading test dir" + directory.getAbsolutePath());
        for (File file : directory.listFiles()) {
            if (!file.isDirectory()) {
                data.add(readTestData(file.getName()));
            }
        }
        return data;
    }

    /**
     * Returns a list with all files in the testfile directory.
     * 
     * @return all files of the testfile directory
     */
    public static File[] getTestiles() {
        return Paths.get(RESOURCE_DIR, TEST_FILE_DIR).toFile().listFiles();
    }

    /**
     * Parses the report (by pev) and creates a TestData instance.
     * 
     * @param filename
     * @return
     * @throws IOException
     */
    public static TestData readTestData(String filename) throws IOException {

        TestData data = new TestData();
        data.filename = filename;
        logger.debug("reading file report " + filename);
        Path testfile = Paths.get(RESOURCE_DIR, TEST_REPORTS_DIR, filename);
        System.out.println("reading test file " + testfile.toString());

        try (BufferedReader reader = Files.newBufferedReader(testfile,
                Charset.forName("UTF-8"))) {
            String line = null;
            while ((line = reader.readLine()) != null) {
                if (line.contains("DOS header") || line.contains("DOS Header")) {
                    readDOSAndPESig(data, reader);
                }
                if (line.contains("COFF header") || line.contains("COFF/File header")) {
                    data.coff = readCOFF(reader);
                }
                if (line.contains("Optional (PE) header") || line.contains("Optional/Image header")) {
                    readOpt(data, reader);
                }
                if (line.contains("Data directories") || line.contains("Directory")) {
                    readDataDirs(data, reader);
                }
                if (line.contains("Sections")){
                    readSections(data, reader);
                    readResourceTypes(data, reader);
                }
            }

        }
        return data;
    }

    private static void readResourceTypes(TestData data, BufferedReader reader) throws IOException {
        data.resTypes = new ArrayList<>();
        String line = null;
        while((line = reader.readLine()) != null) {
            if(line.contains("Type")) {
                String[] split = line.split(":");
                data.resTypes.add(split[1].trim());
            }
        }
    }

    private static void readSections(TestData data, BufferedReader reader)
            throws IOException {
        logger.debug("Reading sections");
        data.sections = new ArrayList<>();
        String line;
        int number = 0;
        while ((line = reader.readLine()) != null) {
            number++;
            String[] split = line.split(":");
            if (split[0].contains("Resources")) {
                break;
            }
            SectionHeader entry = readSectionEntry(reader, line, number);
            if (entry != null) {
                data.sections.add(entry);
            }
        }
    }

    private static SectionHeader readSectionEntry(BufferedReader reader,
            String line, int number) throws IOException {
        String name = "";
        Map<SectionHeaderKey, StandardField> entries = new HashMap<>();
        int entryCounter = 0;
        while (line != null) {
            String[] split = line.split(":");
            if (split.length < 2) {
                break;
            }
            if (split[0].contains("Name")) {
                name = split[1].trim();
                logger.debug("read section name " + name);
            } else {
                long value = convertToLong(split[1]);
                String keyString = split[0].trim();
                SectionHeaderKey key = getSectionKeyFor(keyString);
                if (key != null) {
                    entries.put(key, new StandardField(key, null, value, 0, 0));
                    entryCounter++;
                } else {
                    logger.warn("key was null for " + line);
                }
            }
            line = reader.readLine();
        }
        if (entryCounter == 5) { // exactly 5 values are in the pev report
            return new SectionHeader(entries, number, -1, name, -1);
        }
        return null;
    }

    private static void readDataDirs(TestData data, BufferedReader reader)
            throws IOException {
        List<DataDirEntry> dataDirs = new ArrayList<DataDirEntry>();
        DataDirEntry entry = readDataDirEntry(reader);
        while (entry != null) {
            dataDirs.add(entry);
            entry = readDataDirEntry(reader);
        }
        data.dataDir = dataDirs;

    }

    private static DataDirEntry readDataDirEntry(BufferedReader reader)
            throws IOException {
        String line = null;
        String name = null;
        Integer virtualAddress = null;
        Integer size = null;
        while ((line = reader.readLine()) != null) {
            if(line.contains("Directory")) {
                continue;
            }
            String[] split = line.split(":");
            if (split.length < 2 || split[0].contains("Sections") || line.contains("Imported functions")) {
                logger.debug("Data Dir entry reading finished. Returning");
                break;
            }
            name = split[0].trim();
            String[] rest = split[1].split("\\(");
            virtualAddress = convertToInt(rest[0].trim());
            size = convertToInt(rest[1].trim());
            DataDirectoryKey key = getDataDirKeyForName(name);
            if (key != null) {
                logger.debug("Read Data Dir entry: " + name + " va: " + virtualAddress + " size: " + size);
                return new DataDirEntry(key, virtualAddress, size, -1);
            } else {
                logger.warn("null data dir key returned for: " + name
                            + " and " + line);
                return null;
            }
        }
        return null;
    }

    private static void readDOSAndPESig(TestData data, BufferedReader reader)
            throws IOException {
        logger.debug("read DOS and PE sig");
        Map<MSDOSHeaderKey, String> dos = new HashMap<>();
        String line = null;
        while ((line = reader.readLine()) != null) {
            String[] split = line.split(":");
            if (split.length < 2) {
                break;
            }
            if (split[0].contains("PE header offset")) {
                data.peoffset = convertToInt(split[1].trim());
                continue;
            }
            MSDOSHeaderKey key = getMSDOSKeyFor(split[0]);
            if (key == null) {
                continue;
            }
            String value = split[1].trim();
            dos.put(key, value);
        }
        data.dos = dos;
    }

    private static void readOpt(TestData data, BufferedReader reader)
            throws IOException {
        String line = null;
        data.windowsOpt = new HashMap<>();
        data.standardOpt = new HashMap<>();
        while ((line = reader.readLine()) != null) {
            String[] split = line.split(":");
            if (line.contains("Data directories")) {
                break;
            }
            if (split.length < 2) {
                continue;
            }
            String value = split[1].trim().split("\\s")[0]; // remove everything
                                                            // after whitespace
            StandardFieldEntryKey sKey = getStandardKeyFor(split[0]);
            if (sKey == null) {
                WindowsEntryKey wKey = getWindowsKeyFor(split[0]);
                if (wKey != null) {
                    data.windowsOpt.put(wKey, value);
                }
            } else {
                data.standardOpt.put(sKey, value);
            }
            if (line.contains("Data-dictionary entries")) {
                break;
            }
        }
    }

    private static Map<COFFHeaderKey, String> readCOFF(BufferedReader reader)
            throws IOException {
        Map<COFFHeaderKey, String> coff = new HashMap<>();
        String line = null;
        while ((line = reader.readLine()) != null) {
            String[] split = line.split(":");
            if (split.length < 2) {
                break;
            }
            COFFHeaderKey key = getCOFFHeaderKeyFor(split[0]);
            if (key == null) {
                continue;
            }
            String value = split[1].trim().split("\\s")[0]; // remove everything
                                                            // after whitespace
            coff.put(key, value);
        }
        return coff;
    }

    /************************************************************************
     * The following methods are just translator for the pev report testfiles,
     * they have no use otherwise
     * ********************************************************************/
    // TODO test for correctly extracted entry number
    private static MSDOSHeaderKey getMSDOSKeyFor(String string) {
        if (string.contains("Bytes in last page")) {
            logger.debug("Last page size found");
            return MSDOSHeaderKey.LAST_PAGE_SIZE;
        }
        if (string.contains("Pages in file")) {
            logger.debug("Pages in file found");
            return MSDOSHeaderKey.FILE_PAGES;
        }
        if (string.contains("Relocations")) {
            logger.debug("Relocations found");
            return MSDOSHeaderKey.RELOCATION_ITEMS;
        }
        if (string.contains("Size of header in paragraphs")) {
            logger.debug("Header paragraphs found");
            return MSDOSHeaderKey.HEADER_PARAGRAPHS;
        }
        if (string.contains("Minimum extra paragraphs")) {
            logger.debug("Minalloc found");
            return MSDOSHeaderKey.MINALLOC;
        }
        if (string.contains("Maximum extra paragraphs")) {
            logger.debug("Maxalloc found");
            return MSDOSHeaderKey.MAXALLOC;
        }
        if (string.contains("SS value")) {
            logger.debug("Initial SS found");
            return MSDOSHeaderKey.INITIAL_SS;
        }
        if (string.contains("IP value")) {
            logger.debug("Initial IP found");
            return MSDOSHeaderKey.INITIAL_IP;
        }
        if (string.contains("SP value")) {
            logger.debug("Initial SP found");
            return MSDOSHeaderKey.INITIAL_SP;
        }
        if (string.contains("CS value")) {
            logger.debug("Pre relocated initial CS found");
            return MSDOSHeaderKey.PRE_RELOCATED_INITIAL_CS;
        }
        if (string.contains("Address of relocation table")) {
            logger.debug("Relocation table offset found");
            return MSDOSHeaderKey.RELOCATION_TABLE_OFFSET;
        }
        if (string.contains("Overlay number")) {
            logger.debug("Overlay nr found");
            return MSDOSHeaderKey.OVERLAY_NR;
        }
        if (string.contains("OEM identifier")) {
            logger.debug("OEM identifer found, but discarded");
            return null;
        }
        if (string.contains("OEM information")) {
            logger.debug("OEM information found, but discarded");
            return null;
        }
        if (string.contains("Magic number")) { // not testing MZ signature is on
                                               // purpose
            logger.debug("Magic number found, but discarded");
            return null;
        }
        // TODO: OEM identifier and OEM information missing in MSDOSspec
        // TODO: not covered in testfiles: complemented_checksum and
        // signature_word
        logger.warn("missing msdos key: " + string);
        return null;
    }

    private static COFFHeaderKey getCOFFHeaderKeyFor(String string) {
        if (string.contains("Machine")) {
            logger.debug("Machine found");
            return COFFHeaderKey.MACHINE;
        }
        if (string.contains("Number of sections")) {
            logger.debug("Section Nr found");
            return COFFHeaderKey.SECTION_NR;
        }
        if (string.contains("Date/time stamp")) {
            logger.debug("Timestamp found");
            return COFFHeaderKey.TIME_DATE;
        }
        if (string.contains("Symbol Table offset")) {
            logger.debug("Symbol Table Offset found but discarded - TODO?");
            return null; // TODO ?
        }
        if (string.contains("Number of symbols")) {
            logger.debug("Nr of Symbols found but discarded - TODO?");
            return null; // TODO ?
        }
        if (string.contains("Size of optional header")) {
            logger.debug("Size of Optional Header found");
            return COFFHeaderKey.SIZE_OF_OPT_HEADER;
        }
        if (string.contains("Characteristics")) {
            logger.debug("Characteristics found");
            return COFFHeaderKey.CHARACTERISTICS;
        }
        logger.warn("missing coff header key: " + string);
        return null;
    }

    private static StandardFieldEntryKey getStandardKeyFor(String string) {
        if (string.contains("Magic number")) {
            logger.debug("Magic number found");
            return StandardFieldEntryKey.MAGIC_NUMBER;
        }
        if (string.contains("Linker major version")) {
            logger.debug("Linker major version found");
            return StandardFieldEntryKey.MAJOR_LINKER_VERSION;
        }
        if (string.contains("Linker minor version")) {
            logger.debug("Linker minor version found");
            return StandardFieldEntryKey.MINOR_LINKER_VERSION;
        }
        if (string.contains("Entry point") || string.contains("Entrypoint")) {
            logger.debug("Entrypoint found");
            return StandardFieldEntryKey.ADDR_OF_ENTRY_POINT;
        }
        if (string.contains("Address of .code") || string.contains("Address of .text section")) {
            logger.debug("Base of Code found");
            return StandardFieldEntryKey.BASE_OF_CODE;
        }
        if (string.contains("Address of .data")) {
            logger.debug("Base of data found");
            return StandardFieldEntryKey.BASE_OF_DATA;
        }
        if (string.contains("Size of .code") || string.contains("Size of .text")) {
            logger.debug("Size of code found");
            return StandardFieldEntryKey.SIZE_OF_CODE;
        }
        if (string.contains("Size of .data")) {
            logger.debug("Size of data found");
            return StandardFieldEntryKey.SIZE_OF_INIT_DATA;
        }
        if (string.contains("Size of .bss")) {
            logger.debug("Size of Uninit Data found");
            return StandardFieldEntryKey.SIZE_OF_UNINIT_DATA;
        }
        if (getWindowsKeyFor(string) == null) {
            logger.warn("missing standard field key: " + string);
        }
        return null;
    }

    private static WindowsEntryKey getWindowsKeyFor(String string) {
        if (string.contains("checksum") || string.contains("Checksum")) {
            logger.debug("Checksum found");
            return WindowsEntryKey.CHECKSUM;
        }
        if (string.contains("DLL characteristics")) {
            logger.debug("DLL Characteristics found");
            return WindowsEntryKey.DLL_CHARACTERISTICS;
        }
        if (string.contains("Alignment factor")) {
            logger.debug("File alignment found");
            return WindowsEntryKey.FILE_ALIGNMENT;
        }
        if (string.contains("Imagebase") || string.contains("ImageBase")) {
            logger.debug("Image base found");
            return WindowsEntryKey.IMAGE_BASE;
        }
        if (string.contains("Address of .code")) { //TODO is that correct?
            logger.debug("Loader flags/addr of .code found");
            return WindowsEntryKey.LOADER_FLAGS;
        }
        if (string.contains("Major version of image")) {
            logger.debug("Major image version found");
            return WindowsEntryKey.MAJOR_IMAGE_VERSION;
        }
        if (string.contains("Major version of required OS")) {
            logger.debug("Major OS version found");
            return WindowsEntryKey.MAJOR_OS_VERSION;
        }
        if (string.contains("Major version of subsystem")) {
            logger.debug("Major subsystem version found");
            return WindowsEntryKey.MAJOR_SUBSYSTEM_VERSION;
        }
        if (string.contains("Minor version of image")) {
            logger.debug("Minor image version found");
            return WindowsEntryKey.MINOR_IMAGE_VERSION;
        }
        if (string.contains("Minor version of required OS")) {
            logger.debug("Minor OS version found");
            return WindowsEntryKey.MINOR_OS_VERSION;
        }
        if (string.contains("Minor version of subsystem")) {
            logger.debug("Minor subsystem version");
            return WindowsEntryKey.MINOR_SUBSYSTEM_VERSION;
        }
        if (string.contains("Data-dictionary entries")) {
            logger.debug("Nr of RVA and sizes found");
            return WindowsEntryKey.NUMBER_OF_RVA_AND_SIZES;
        }
        if (string.contains("Alignment of sections")) {
            logger.debug("Section alignment found");
            return WindowsEntryKey.SECTION_ALIGNMENT;
        }
        if (string.contains("Size of headers")) {
            logger.debug("Size of headers found");
            return WindowsEntryKey.SIZE_OF_HEADERS;
        }
        if (string.contains("Size of heap space to commit")) {
            logger.debug("Size of heap commit found");
            return WindowsEntryKey.SIZE_OF_HEAP_COMMIT;
        }
        if (string.contains("Size of heap space to reserve")) {
            logger.debug("Size of heap reserve found");
            return WindowsEntryKey.SIZE_OF_HEAP_RESERVE;
        }
        if (string.contains("Size of image")) {
            logger.debug("Size of image found");
            return WindowsEntryKey.SIZE_OF_IMAGE;
        }
        if (string.contains("Size of stack to commit")) {
            logger.debug("Size of stack to commit found");
            return WindowsEntryKey.SIZE_OF_STACK_COMMIT;
        }
        if (string.contains("Size of stack to reserve")) {
            logger.debug("Size of stack reserve found");
            return WindowsEntryKey.SIZE_OF_STACK_RESERVE;
        }
        if (string.contains("Subsystem required")) {
            logger.debug("Subsystem found");
            return WindowsEntryKey.SUBSYSTEM;
        }
        // if (string.contains("")) { TODO missing in report (?)
        // return WindowsEntryKey.WIN32_VERSION_VALUE;
        // }
        logger.warn("missing windows key: " + string);
        return null;
    }

    private static DataDirectoryKey getDataDirKeyForName(String name) {
        if (name.contains("Import Table") || name.contains("IMAGE_DIRECTORY_ENTRY_IMPORT")) {
            return DataDirectoryKey.IMPORT_TABLE;
        }
        if (name.contains("Resource Table") || name.contains("IMAGE_DIRECTORY_ENTRY_RESOURCE")) {
            return DataDirectoryKey.RESOURCE_TABLE;
        }
        if (name.contains("Certificate") || name.contains("IMAGE_DIRECTORY_ENTRY_SECURITY")) {
            return DataDirectoryKey.CERTIFICATE_TABLE;
        }
        if (name.contains("Debug") || name.contains("IMAGE_DIRECTORY_ENTRY_DEBUG")) {
            return DataDirectoryKey.DEBUG;
        }
        if (name.contains("Load Config Table") || name.contains("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG")) {
            return DataDirectoryKey.LOAD_CONFIG_TABLE;
        }
        if (name.contains("Import Address Table") || name.contains("IMAGE_DIRECTORY_ENTRY_IAT")) {
            return DataDirectoryKey.IAT;
        }
        if (name.contains("TLS")) {
            return DataDirectoryKey.TLS_TABLE;
        }
        if (name.contains("Exception")) {
            return DataDirectoryKey.EXCEPTION_TABLE;
        }
        if (name.contains("Architecture")) {
            return DataDirectoryKey.ARCHITECTURE;
        }
        if (name.contains("Relocation") || name.contains("IMAGE_DIRECTORY_ENTRY_BASERELOC")) {
            return DataDirectoryKey.BASE_RELOCATION_TABLE;
        }
        if (name.contains("Bound Import")) {
            return DataDirectoryKey.BOUND_IMPORT;
        }
        if (name.contains("Runtime Header") || name.contains("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR")) {
            return DataDirectoryKey.CLR_RUNTIME_HEADER;
        }
        if (name.contains("Delay Import")) {
            return DataDirectoryKey.DELAY_IMPORT_DESCRIPTOR;
        }
        if (name.contains("Export")) {
            return DataDirectoryKey.EXPORT_TABLE;
        }
        if (name.contains("Global")) {
            return DataDirectoryKey.GLOBAL_PTR;
        }
        logger.warn("missing data dir key: " + name);
        return null;
    }

    private static SectionHeaderKey getSectionKeyFor(String name) {
        if (name.contains("Virtual size") || name.contains("Virtual Size")) {
            return SectionHeaderKey.VIRTUAL_SIZE;
        }
        if (name.contains("Virtual address") || name.contains("Virtual Address")) {
            return SectionHeaderKey.VIRTUAL_ADDRESS;
        }
        if (name.contains("Data size") || name.contains("Size Of Raw Data")) {
            return SectionHeaderKey.SIZE_OF_RAW_DATA;
        }
        if (name.contains("Data offset") || name.contains("Pointer To Raw Data")) {
            return SectionHeaderKey.POINTER_TO_RAW_DATA;
        }
        if (name.contains("Number Of Relocations")) {
            return SectionHeaderKey.NUMBER_OF_RELOCATIONS;
        }
        if (name.contains("Characteristics")) {
            return SectionHeaderKey.CHARACTERISTICS;
        }

        logger.warn("missing section table entry " + name);
        return null;
    }

    private static int convertToInt(String val) {
        String value = val.trim().split("\\s")[0].trim();
        if (value.startsWith("0x")) {
            value = value.replace("0x", "");
            return Integer.parseInt(value, 16);
        } else {
            return Integer.parseInt(value);
        }
    }

    private static long convertToLong(String val) {
        String value = val.trim().split("\\s")[0].trim();
        if (value.startsWith("0x")) {
            value = value.replace("0x", "");
            return Long.parseLong(value, 16);
        } else {
            return Long.parseLong(value);
        }
    }

    public static class TestData {

        public Map<MSDOSHeaderKey, String> dos;
        public Map<COFFHeaderKey, String> coff;
        public Map<StandardFieldEntryKey, String> standardOpt;
        public Map<WindowsEntryKey, String> windowsOpt;
        public List<DataDirEntry> dataDir;
        public List<SectionHeader> sections;
        public List<ResourceDataEntry> resources;
        public String filename;
        public int peoffset;
        public List<String> resTypes;
    }

}
