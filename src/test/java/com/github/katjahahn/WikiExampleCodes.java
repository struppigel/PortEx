package com.github.katjahahn;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.imageio.ImageIO;

import com.github.katjahahn.coffheader.COFFFileHeader;
import com.github.katjahahn.coffheader.MachineType;
import com.github.katjahahn.optheader.DataDirEntry;
import com.github.katjahahn.optheader.DataDirectoryKey;
import com.github.katjahahn.sections.SectionLoader;
import com.github.katjahahn.sections.SectionTable;
import com.github.katjahahn.sections.debug.DebugDirTableKey;
import com.github.katjahahn.sections.debug.DebugSection;
import com.github.katjahahn.sections.edata.ExportSection;
import com.github.katjahahn.sections.idata.DirectoryTableEntry;
import com.github.katjahahn.sections.idata.DirectoryTableEntryKey;
import com.github.katjahahn.sections.idata.ImportDLL;
import com.github.katjahahn.sections.idata.ImportSection;
import com.github.katjahahn.sections.idata.NameImport;
import com.github.katjahahn.sections.idata.OrdinalImport;
import com.github.katjahahn.sections.rsrc.DataEntry;
import com.github.katjahahn.sections.rsrc.Resource;
import com.github.katjahahn.sections.rsrc.ResourceDirectoryEntry;
import com.github.katjahahn.sections.rsrc.ResourceDirectoryTable;
import com.github.katjahahn.sections.rsrc.ResourceDirectoryTableKey;
import com.github.katjahahn.sections.rsrc.ResourceSection;
import com.github.katjahahn.sections.rsrc.SubDirEntry;
import com.github.katjahahn.tools.Overlay;
import com.github.katjahahn.tools.Visualizer;
import com.github.katjahahn.tools.anomalies.Anomaly;
import com.github.katjahahn.tools.anomalies.PEAnomalyScanner;
import com.github.katjahahn.tools.sigscanner.Jar2ExeScanner;
import com.github.katjahahn.tools.sigscanner.MatchedSignature;
import com.github.katjahahn.tools.sigscanner.Signature;
import com.github.katjahahn.tools.sigscanner.SignatureScanner;

/**
 * These are the code examples for the PortEx Wiki.
 * <p>
 * If code changes have to be applied here, the Wiki for PortEx has to be
 * updated too.
 * 
 * @author Katja Hahn
 * 
 */
public class WikiExampleCodes {
    
    public void visualizer() throws IOException {
        File file = new File("WinRar.exe");
        PEData data = PELoader.loadPE(file);
        Visualizer visualizer = new Visualizer(data);
        BufferedImage image = visualizer.createImage();
        ImageIO.write(image, "png", new File("image.png"));
        //use parameters
        visualizer.setPixelated(true);
        visualizer.setHeight(800);
        visualizer.setFileWidth(600);
        visualizer.setLegendWidth(300);
        visualizer.setPixelSize(10);
        visualizer.setAdditionalGap(3);
        //set bytes per pixel
        visualizer.setBytesPerPixel(10);
    }
    
    public void fileAnomalies() {
        File file = new File("filepath");
        PEAnomalyScanner scanner = PEAnomalyScanner.newInstance(file);
        System.out.println(scanner.scanReport());
        
        scanner = PEAnomalyScanner.newInstance(file);
        List<Anomaly> anomalies = scanner.getAnomalies();
        for(Anomaly anomaly: anomalies) {
            System.out.println("Anomaly Type: " + anomaly.getType());
            System.out.println("Entry with anomaly: " + anomaly.field());
            System.out.println(anomaly.description());
            System.out.println();
        }
    }

    public void gettingStarted() throws IOException {
        // Header information
        // load the PE file data
        PEData data = PELoader.loadPE(new File("myfile"));

        // get various data from coff file header and print it
        COFFFileHeader coff = data.getCOFFFileHeader();
        MachineType machine = coff.getMachineType();
        Date date = coff.getTimeDate();
        int numberOfSections = coff.getNumberOfSections();
        int optionalHeaderSize = coff.getSizeOfOptionalHeader();

        System.out.println("machine type: "
                + COFFFileHeader.getDescription(machine));
        System.out.println("number of sections: " + numberOfSections);
        System.out.println("size of optional header: " + optionalHeaderSize);
        System.out.println("time date stamp: " + date);

        List<String> characteristics = coff.getCharacteristicsDescriptions();
        System.out.println("characteristics: ");
        for (String characteristic : characteristics) {
            System.out.println("\t* " + characteristic);
        }
        // print all available information of the coff file header
        System.out.println(coff.getInfo());
        // standard section information
        SectionLoader loader = new SectionLoader(data);
        ImportSection idata = loader.loadImportSection();
        System.out.println(idata.getInfo());
        // Miscellaneous
        SectionTable table = data.getSectionTable();
        Map<DataDirectoryKey, DataDirEntry> dataDirEntries = data
                .getOptionalHeader().getDataDirEntries();
        for (DataDirEntry entry : dataDirEntries.values()) {
            System.out.println(entry);
            System.out.println("calculated file offset: "
                    + entry.getFileOffset(table));
            System.out.println("section name: "
                    + entry.getSectionTableEntry(table).getName());
            System.out.println();
        }
    }

    @SuppressWarnings("unused")
    public void resourceSection() throws IOException {
        // Loading
        File file = new File("WinRar.exe");
        PEData data = PELoader.loadPE(file);
        ResourceSection rsrc = new SectionLoader(data).loadResourceSection();
        // Fetching resources
        List<Resource> resources = rsrc.getResources();
        for (Resource r : resources) {
            System.out.println(r);
        }
        // Access to structures of the resource tree
        ResourceDirectoryTable table = rsrc.getResourceTable();
        // Resource directory table header
        Map<ResourceDirectoryTableKey, StandardField> header = table
                .getHeader();
        long majorVersion = header.get(ResourceDirectoryTableKey.MAJOR_VERSION).value;
        // Get values directly
        long majorVers = table
                .getHeaderValue(ResourceDirectoryTableKey.MAJOR_VERSION);
        // Resource directory table entries
        // get a list of all entries, regardless which subtype
        List<ResourceDirectoryEntry> entries = table.getTableEntries();
        // get a list of all data entries
        List<DataEntry> dataEntries = table.getDataEntries();
        // get a list of all subdirectory entries
        List<SubDirEntry> subdirEntries = table.getSubDirEntries();
    }

    public void importSection() throws FileFormatException, IOException {
        File file = new File("WinRar.exe");
        // Print Information
        PEData data = PELoader.loadPE(file);
        SectionLoader loader = new SectionLoader(data);
        ImportSection idata = loader.loadImportSection();
        System.out.println(idata.getInfo());
        // List of imports
        List<ImportDLL> imports = idata.getImports();
        for (ImportDLL dll : imports) {
            System.out.println("Imports from " + dll.getName());
            for (NameImport nameImport : dll.getNameImports()) {
                System.out.print("Name: " + nameImport.name);
                System.out.print(" Hint: " + nameImport.hint);
                System.out.println(" RVA: " + nameImport.rva);
            }

            for (OrdinalImport ordImport : dll.getOrdinalImports()) {
                System.out.println("Ordinal: " + ordImport.ordinal);
            }
            System.out.println();
        }
        // Access to ImportSection structures
        List<DirectoryTableEntry> dirTable = idata.getDirectoryTable();
        for (DirectoryTableEntry tableEntry : dirTable) {
            Map<DirectoryTableEntryKey, StandardField> map = tableEntry
                    .getEntries();

            for (StandardField field : map.values()) {
                System.out.println(field.description + ": " + field.value);
            }
        }
    }

    public void exportSection() throws IOException {
        // Show Information
        File file = new File("src/main/resources/testfiles/DLL2.dll");
        PEData data = PELoader.loadPE(file);
        ExportSection edata = new SectionLoader(data).loadExportSection();
        System.out.println(edata.getInfo());
    }

    @SuppressWarnings("unused")
    public void debugSection() throws IOException {
        File file = new File("src/main/resources/testfiles/ntdll.dll");
        // Print Information
        PEData data = PELoader.loadPE(file);
        SectionLoader loader = new SectionLoader(data);
        DebugSection debug = loader.loadDebugSection();
        System.out.println(debug.getInfo());
        // Get specific values
        Long address = debug.get(DebugDirTableKey.ADDR_OF_RAW_DATA);
        Long size = debug.get(DebugDirTableKey.SIZE_OF_DATA);
        String type = debug.getTypeDescription();
        Date stamp = debug.getTimeDateStamp();
    }

    @SuppressWarnings("unused")
    public void overlay() throws IOException {
        // Overlay recognition
        File file = new File("myfile");
        Overlay overlay = new Overlay(file);
        if (overlay.exists()) {
            System.out.println("overlay detected");
        }
        // Overlay offset and size
        long offset = overlay.getOffset();
        long size = overlay.getSize();
        // Overlay dumping
        byte[] dump = overlay.getDump();
        // Overlay dumping 2
        File outFile = new File("dump.out");
        overlay.dumpTo(outFile);
    }

    public void signatureScanning() {
        // Signature scanning
        SignatureScanner scanner = SignatureScanner.newInstance();
        boolean epOnly = true;
        File file = new File("peid.exe");
        List<String> results = scanner.scanAll(file, epOnly);
        for (String signature : results) {
            System.out.println(signature);
        }
        // Use own database
        List<Signature> signatures = SignatureScanner.loadSignatures(new File(
                "testuserdb.txt"));
        scanner = new SignatureScanner(signatures);
        // Java Wrapper scanning
        Jar2ExeScanner j2eScanner = new Jar2ExeScanner(new File(
                "launch4jexe.exe"));
        System.out.println(j2eScanner.createReport());
        // dump embedded
        List<Long> addresses = j2eScanner.getZipAddresses();
        int i = 0;
        for (Long address : addresses) {
            i++;
            j2eScanner.dumpAt(address, new File("dumped" + i + ".jar"));
        }
        // Detailed signature information
        j2eScanner = new Jar2ExeScanner(new File("launch4jexe.exe"));
        List<MatchedSignature> result = j2eScanner.scan();
        for (MatchedSignature sig : result) {
            System.out.println("name: " + sig.name);
            System.out.println("address: " + sig.address);
            System.out.println("epOnly: " + sig.epOnly);
            System.out.println("signature: " + sig.signature);
            System.out.println();
        }
    }

}
