/*******************************************************************************
 * Copyright 2014 Karsten Philipp Boris Hahn
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package io.github.struppigel;

import io.github.struppigel.parser.*;
import io.github.struppigel.parser.coffheader.COFFFileHeader;
import io.github.struppigel.parser.coffheader.FileCharacteristic;
import io.github.struppigel.parser.coffheader.MachineType;
import io.github.struppigel.parser.sections.SectionLoader;
import io.github.struppigel.parser.sections.debug.*;
import io.github.struppigel.parser.Location;
import io.github.struppigel.parser.sections.debug.CodeviewInfo;
import io.github.struppigel.parser.sections.debug.DebugDirectoryEntry;
import io.github.struppigel.parser.sections.debug.DebugSection;
import io.github.struppigel.parser.sections.edata.ExportEntry;
import io.github.struppigel.parser.sections.edata.ExportNameEntry;
import io.github.struppigel.parser.sections.edata.ExportSection;
import io.github.struppigel.parser.sections.idata.*;
import io.github.struppigel.parser.sections.rsrc.*;
import io.github.struppigel.parser.sections.idata.DirectoryEntry;
import io.github.struppigel.parser.sections.idata.ImportSection;
import io.github.struppigel.parser.sections.rsrc.*;
import io.github.struppigel.parser.sections.rsrc.icon.GroupIconResource;
import io.github.struppigel.parser.sections.rsrc.icon.IcoFile;
import io.github.struppigel.parser.sections.rsrc.icon.IconParser;
import io.github.struppigel.parser.sections.rsrc.version.VersionInfo;
import io.github.struppigel.tools.*;
import io.github.struppigel.tools.ChiSquared;
import io.github.struppigel.tools.Overlay;
import io.github.struppigel.tools.ReportCreator;
import io.github.struppigel.tools.ShannonEntropy;
import io.github.struppigel.tools.anomalies.Anomaly;
import io.github.struppigel.tools.anomalies.PEAnomalyScanner;
import io.github.struppigel.tools.sigscanner.FileTypeScanner;
import io.github.struppigel.tools.sigscanner.Jar2ExeScanner;
import io.github.struppigel.tools.sigscanner.LocationKind;
import io.github.struppigel.tools.sigscanner.PEiDImporter;
import io.github.struppigel.tools.sigscanner.SignatureDatabase;
import io.github.struppigel.tools.sigscanner.SignatureMatch;
import io.github.struppigel.tools.sigscanner.SignatureScanner;
import io.github.struppigel.tools.layout.FileRegion;
import io.github.struppigel.tools.layout.SignatureHit;
import io.github.struppigel.tools.layout.StructureMap;
import io.github.struppigel.tools.layout.StructureMapBuilder;
import io.github.struppigel.tools.visualizer.ColorableItem;
import io.github.struppigel.tools.visualizer.ImageUtil;
import io.github.struppigel.tools.visualizer.Visualizer;
import io.github.struppigel.tools.visualizer.VisualizerBuilder;
import io.github.struppigel.tools.visualizer.engine.ByteStatistics;
import io.github.struppigel.tools.visualizer.engine.CachedByteSource;
import io.github.struppigel.tools.visualizer.engine.FileVisualization;
import io.github.struppigel.tools.visualizer.engine.ProgressListener;
import io.github.struppigel.tools.visualizer.engine.ViewMapping;
import io.github.struppigel.tools.visualizer.render.RegionColorScheme;
import io.github.struppigel.tools.visualizer.render.RenderStyle;
import io.github.struppigel.tools.visualizer.render.Track;
import io.github.struppigel.tools.visualizer.render.VisualizationRenderer;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * These are the code examples for the PortEx Wiki.
 * <p>
 * If code changes have to be applied here, the Wiki for PortEx has to be
 * updated too.
 * 
 * @author Karsten Hahn
 * 
 */
public class WikiExampleCodes {

    public static void main(String[] args) throws IOException {
        resourceSection();
    }

    public static void versionInfo() throws IOException {
        File file = new File("WinRar.exe");
        List<VersionInfo> info = VersionInfo.parseFromResources(file);
        for(VersionInfo i : info) {
            Map<String, String> strings = i.getVersionStrings();
            for (Map.Entry<String,String> entry : strings.entrySet()) {
                System.out.print(entry.getKey() + ": ");
                System.out.println(entry.getValue());
            }
        }

        // Alternative way
        PEData data = PELoader.loadPE(file);
        Optional<VersionInfo> versionInfoOpt = data.loadVersionInfo();
        if(versionInfoOpt.isPresent()) {
            Map<String, String> strings = versionInfoOpt.get().getVersionStrings();
        }
    }

    public static void entropy() throws IOException {
        PEData data = PELoader.loadPE(new File("myfile.exe"));
        int nrOfSections = data.getCOFFFileHeader().getNumberOfSections();
        ShannonEntropy entropy = new ShannonEntropy(data);
        for(int i = 1; i < nrOfSections; i++) {
            double sectionEntropy = entropy.forSection(i);
            System.out.println("Entropy for Section " + i + ": " + sectionEntropy);
        }
    }

    public static void entropy2(){
        ShannonEntropy entropy = ShannonEntropy.newInstance(new File("myfile.exe"));
        System.out.println(entropy.forFile());
    }

    public static void chiSquared() throws IOException {
        PEData data = PELoader.loadPE(new File("myfile.exe"));
        ChiSquared chi2 = new ChiSquared(data);
        double fileChi = chi2.forFile();
        System.out.println("Chi2 for file " + fileChi);
        int nrOfSections = data.getCOFFFileHeader().getNumberOfSections();
        for(int i = 1; i < nrOfSections; i++) {
            double sectionChi2 = chi2.forSection(i);
            System.out.println("Section " + i + " has chi2: " + sectionChi2);
        }
    }

    public static void imphash() {
        File file = new File("WinRar.exe");
        // Get hash as byte array
        byte[] imphashArray = ImpHash.calculate(file);
        // Get hash as hex string
        String imphashStr = ImpHash.createString(file);
        System.out.println(imphashStr);
    }

    @SuppressWarnings("unused")
    public static void visualizer() throws IOException {
        File peFile = new File("WinRar.exe");
        Visualizer visualizer = new VisualizerBuilder().build();
        visualizer.writeImage(peFile, new File("image.png"));
        // use parameters
        visualizer = new VisualizerBuilder()
                .setPixelated(true)
                .setHeight(800)
                .setFileWidth(600)
                .setLegendWidth(300)
                .setPixelSize(10)
                .setAdditionalGap(3)
                .setBytesPerPixel(10, peFile.length())
                .setColor(ColorableItem.SECTION_TABLE, Color.BLUE)
                .build();

        // change bytes per square pixel
        new VisualizerBuilder().setBytesPerPixel(10, peFile.length()).build();
        // create an entropy image
        BufferedImage entropyImage = visualizer.createEntropyImage(peFile);
        // create appended entropy & structure image
        BufferedImage leftImage = visualizer.createEntropyImage(peFile);
        BufferedImage rightImage = visualizer.createImage(peFile);
        BufferedImage appendedImage = ImageUtil.appendImages(leftImage,
                rightImage);
        // create byteplot
        BufferedImage bytePlot = visualizer.createBytePlot(peFile);
        BufferedImage legendImage = visualizer.createLegendImage(true, false, false);
        BufferedImage appendedImage2 = ImageUtil.appendImages(bytePlot, legendImage);
        ImageIO.write(appendedImage2, "png", new File("outfile.png"));

        // parse once and create all images from the PEData, in the look of the interactive visualization
        PEData data = PELoader.loadPE(peFile);
        Visualizer newLook = new VisualizerBuilder().setLegacyStyle(false).build();
        BufferedImage all = ImageUtil.appendImages(newLook.createBytePlot(data), newLook.createEntropyImage(data));
        all = ImageUtil.appendImages(all, newLook.createImage(data));
        all = ImageUtil.appendImages(all, newLook.createLegendImage(data, true, true, true));
        ImageIO.write(all, "png", new File("all.png"));
    }

    @SuppressWarnings("unused")
    public static void structureMap() throws IOException {
        PEData data = PELoader.loadPE(new File("WinRar.exe"));
        // which structures are at an offset, innermost first
        StructureMap map = StructureMap.of(data);
        for (FileRegion region : map.regionsAt(0x200)) {
            System.out.println(region.getPath() + " " + region + " " + region.getAttributes());
        }
        // all structures as a tree
        System.out.println(map.getReport());
        // with anomalies and signature matches as markers
        StructureMap marked = new StructureMapBuilder(data)
                .withAnomalies(PEAnomalyScanner.newInstance(data).getAnomalies())
                .withSignatureMatches(SignatureHit.fromMatches(data.getSignatureMatches()))
                .build();
        // render the structures of the first 0x400 bytes, one byte per cell
        ByteStatistics stats = new ByteStatistics(data.getFile());
        stats.compute(ProgressListener.NONE);
        try (CachedByteSource source = new CachedByteSource(data.getFile())) {
            FileVisualization vis = new FileVisualization(marked, stats, source, RegionColorScheme.of(marked));
            ViewMapping mapping = new ViewMapping(data.getFile().length(), 0, 1, 16);
            BufferedImage image = VisualizationRenderer.renderComposite(vis, mapping, 0, 64,
                    Arrays.asList(Track.BYTEPLOT, Track.ENTROPY, Track.STRUCTURE, Track.HEX), 8, 14,
                    RenderStyle.defaults(), true);
            ImageIO.write(image, "png", new File("headers.png"));
        }
    }

    public static void fileAnomalies() {
        File file = new File("/home/deque/portextestfiles/testfiles/WinRar.exe");
        PEAnomalyScanner scanner = PEAnomalyScanner.newInstance(file);
        System.out.println(scanner.scanReport());

        scanner = PEAnomalyScanner.newInstance(file);
        List<Anomaly> anomalies = scanner.getAnomalies();
        for (Anomaly anomaly : anomalies) {
            System.out.println("Type: " + anomaly.getType());
            System.out.println("Subtype: " + anomaly.subtype());
            System.out.println("Field or structure with anomaly: "
                    + anomaly.key());
            System.out.println(anomaly.description());
            System.out.println();
        }
    }

    @SuppressWarnings("unused")
    public static void gettingStarted() throws IOException {
        // Header information
        // load the PE file data
        PEData data = PELoader.loadPE(new File("myfile"));

        // Print report
        ReportCreator reporter = new ReportCreator(data);
        reporter.printReport();

        // Get report parts
        String anomalyReport = reporter.anomalyReport();
        String importsReport = reporter.importsReport();

        // get various data from coff file header and print it
        COFFFileHeader coff = data.getCOFFFileHeader();
        MachineType machine = coff.getMachineType();
        Date date = coff.getTimeDate();
        int numberOfSections = coff.getNumberOfSections();
        int optionalHeaderSize = coff.getSizeOfOptionalHeader();

        System.out.println("machine type: " + machine.getDescription());
        System.out.println("number of sections: " + numberOfSections);
        System.out.println("size of optional header: " + optionalHeaderSize);
        System.out.println("time date stamp: " + date);

        List<FileCharacteristic> characteristics = coff.getCharacteristics();
        System.out.println("characteristics: ");
        for (FileCharacteristic characteristic : characteristics) {
            System.out.println("\t* " + characteristic.getDescription());
        }
    }

    @SuppressWarnings("unused")
    public static void resourceSection() throws IOException {
        // Loading
        File file = new File("/home/katja/samples/VirMC.exe");
        PEData data = PELoader.loadPE(file);
        ResourceSection rsrc = new SectionLoader(data).loadResourceSection();
        // Alternative loading
        List<Resource> resources = data.loadResources();
        // Fetching resources
        List<Resource> resources2 = rsrc.getResources();
        for (Resource r : resources) {
            System.out.println(r);
        }
        // Getting raw data
        Resource resource = resources.get(0);
        Location loc = resource.rawBytesLocation();
        long offset = loc.from();
        assert loc.size() == (int) loc.size();
        int size = (int) loc.size();
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            byte[] bytes = IOUtil.loadBytes(offset, size, raf);
            // print as hex string
            System.out.println(ByteArrayUtil.byteToHex(bytes));
            // print as string (e.g. for ASCII resources)
            System.out.println(new String(bytes));
        }
        // Extraction of ICO files
        List<GroupIconResource> grpIcoResources = IconParser.extractGroupIcons(file);
        int nr = 0;
        for(GroupIconResource grpIconResource : grpIcoResources) { 
        	nr++;
        	IcoFile icoFile = grpIconResource.toIcoFile();
        	File dest = new File("/home/katja/ico/icon" + nr + ".ico");
        	icoFile.saveTo(dest);
        	System.out.println("ico file " + dest.getName() + " written");
        }
        
        // Alternative extraction of icons and obtaining them as byte array or stream
        List<IcoFile> icons = data.loadIcons();
        for(IcoFile i : icons) {
            byte[] iconBytes = i.getBytes();
            InputStream iconStream = i.getInputStream();
        }
        
        // Access to structures of the resource tree
        ResourceDirectory tree = rsrc.getResourceTree();
        // Resource directory table header
        Map<ResourceDirectoryKey, StandardField> header = tree.getHeader();
        long majorVersion = header.get(ResourceDirectoryKey.MAJOR_VERSION)
                .getValue();
        // Get values directly
        long majorVers = tree
                .getHeaderValue(ResourceDirectoryKey.MAJOR_VERSION);
        // Resource directory table entries
        // get a list of all entries, regardless which subtype
        List<ResourceDirectoryEntry> entries = tree.getEntries();
        // get a list of all data entries
        List<DataEntry> dataEntries = tree.getDataEntries();
        // get a list of all subdirectory entries
        List<SubDirEntry> subdirEntries = tree.getSubDirEntries();
    }

    public static void importSection() throws FileFormatException, IOException {
        File file = new File("WinRar.exe");
        // Print Information
        PEData data = PELoader.loadPE(file);
        ReportCreator reporter = new ReportCreator(data);
        System.out.println(reporter.importsReport());

        // Loading imports since 4.0.0
        List<ImportDLL> importList = data.loadImports();

        // Loading the imports before 4.0.0
        SectionLoader loader = new SectionLoader(data);
        ImportSection idata = loader.loadImportSection();
        List<ImportDLL> imports = idata.getImports();

        // printing import information
        for (ImportDLL dll : imports) {
            System.out.println("Imports from " + dll.getName());
            for (NameImport nameImport : dll.getNameImports()) {
                System.out.print("Name: " + nameImport.getName());
                System.out.print(" Hint: " + nameImport.getHint());
                System.out.println(" RVA: " + nameImport.getRVA());
            }

            for (OrdinalImport ordImport : dll.getOrdinalImports()) {
                System.out.println("Ordinal: " + ordImport.getOrdinal());
            }
            System.out.println();
        }

        // Access to ImportSection structures
        List<DirectoryEntry> dirTable = idata.getDirectory();
        for (DirectoryEntry tableEntry : dirTable) {
            Map<DirectoryEntryKey, StandardField> map = tableEntry.getEntries();

            for (StandardField field : map.values()) {
                System.out.println(field.getDescription() + ": "
                        + field.getValue());
            }
        }
    }

    @SuppressWarnings("unused")
    public static void exportSection() throws IOException {
        // Show Information
        File file = new File("src/main/resources/testfiles/DLL2.dll");
        String report = ReportCreator.newInstance(file).exportsReport();
        System.out.println(report);
        // Loading the export section
        PEData data = PELoader.loadPE(file);
        ExportSection edata = new SectionLoader(data).loadExportSection();
        // since 4.0.0 there is a convenience function to get a list of all exports:
        PEData pedata = PELoader.loadPE(file);
        List<ExportEntry> exports = pedata.loadExports();
        for(ExportEntry export : exports) {
            int ordinal = export.ordinal();
            long rva = export.symbolRVA();
            String name = ((ExportNameEntry) export).name();
        }
    }

    @SuppressWarnings("unused")
    public static void debugSection() throws IOException {
        File file = new File("src/main/resources/testfiles/ntdll.dll");
        // Print Information
        String report = ReportCreator.newInstance(file).debugReport();
        System.out.println(report);

        // Get specific debug directory values of a specific type (here Codeview)
        PEData data = PELoader.loadPE(file);
        SectionLoader loader = new SectionLoader(data);
        DebugSection debugSection = loader.loadDebugSection();
        Stream<DebugDirectoryEntry> debugStream = debugSection.getEntries().stream();
        DebugDirectoryEntry codeViewEntry = debugStream.filter(d -> d.getDebugType() == DebugType.CODEVIEW).findFirst().get();
        Long address = codeViewEntry.get(DebugDirectoryKey.ADDR_OF_RAW_DATA);
        Long size = codeViewEntry.get(DebugDirectoryKey.SIZE_OF_DATA);
        String type = codeViewEntry.getTypeDescription();
        Date stamp = codeViewEntry.getTimeDateStamp();

        // Read Codeview info
        CodeviewInfo codeView = data.loadCodeViewInfo().get();
        byte[] guid = codeView.guid();
        String path = codeView.filePath();
        long age = codeView.age();

        // Load PDB path
        String debugPath = data.loadPDBPath();
    }

    @SuppressWarnings("unused")
    public static void overlay() throws IOException {
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

        // scan overlay signatures
        PEData data = PELoader.loadPE(file);
        List<SignatureMatch> overlaySignatures = data.getSignatureMatches(LocationKind.OVERLAY);
        overlaySignatures.forEach(System.out::println);
    }

    public static void signatureScanning() throws IOException {
        // Signature scanning with the default signatures
        File file = new File("peid.exe");
        PEData data = PELoader.loadPE(file);
        for (SignatureMatch match : data.getSignatureMatches()) {
            System.out.println(match);
        }
        // only the entry point
        List<SignatureMatch> epMatches = data.getSignatureMatches(LocationKind.ENTRY_POINT);
        // Use own database, see docs/SIGNATURES.md for the format
        SignatureDatabase db = SignatureDatabase.load(new File("mysignatures.sig"));
        SignatureScanner scanner = new SignatureScanner(db);
        List<SignatureMatch> matches = scanner.scan(data);
        // Import a PEiD database
        SignatureDatabase peid = PEiDImporter.load(new File("userdb.txt"));
        matches = new SignatureScanner(peid).scan(data, LocationKind.ENTRY_POINT);
        // File type of files that are no PE files
        List<SignatureMatch> fileTypes = FileTypeScanner.scan(new File("unknown.bin"));
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
        List<SignatureMatch> result = j2eScanner.scan();
        for (SignatureMatch sig : result) {
            System.out.println("name: " + sig.getName());
            System.out.println("address: " + sig.getOffset());
            System.out.println("location: " + sig.getLocationLabel());
            System.out.println("pattern: " + sig.getClauseMatches().get(0).getClause().getPattern());
            System.out.println();
        }
    }

}
