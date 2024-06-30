/*******************************************************************************
 * Copyright 2014 Karsten Philipp Boris Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   <a href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</a>
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/

package com.github.struppigel.parser;

import com.github.struppigel.parser.coffheader.COFFFileHeader;
import com.github.struppigel.parser.msdos.MSDOSHeader;
import com.github.struppigel.parser.msdos.MSDOSLoadModule;
import com.github.struppigel.parser.optheader.OptionalHeader;
import com.github.struppigel.parser.sections.SectionLoader;
import com.github.struppigel.parser.sections.SectionTable;
import com.github.struppigel.parser.sections.clr.CLRSection;
import com.github.struppigel.parser.sections.debug.CodeviewInfo;
import com.github.struppigel.parser.sections.debug.DebugSection;
import com.github.struppigel.parser.sections.edata.ExportEntry;
import com.github.struppigel.parser.sections.edata.ExportSection;
import com.github.struppigel.parser.sections.idata.ImportDLL;
import com.github.struppigel.parser.sections.idata.ImportSection;
import com.github.struppigel.parser.sections.rsrc.ID;
import com.github.struppigel.parser.sections.rsrc.Level;
import com.github.struppigel.parser.sections.rsrc.Resource;
import com.github.struppigel.parser.sections.rsrc.ResourceSection;
import com.github.struppigel.parser.sections.rsrc.icon.IcoFile;
import com.github.struppigel.parser.sections.rsrc.icon.IconParser;
import com.github.struppigel.parser.sections.rsrc.version.VersionInfo;
import com.github.struppigel.tools.ReportCreator;
import com.github.struppigel.tools.sigscanner.MatchedSignature;
import com.github.struppigel.tools.sigscanner.SignatureScannerManager;
import com.google.common.annotations.Beta;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Container that collects and holds the main information of a PE file.
 * <p>
 * It is constructed by the PELoader and returned to the caller as result from
 * scanning the PE File information.
 *
 * @author Katja Hahn
 */
public class PEData {

    private static final Logger logger = LogManager.getLogger(PEData.class
            .getName());
    private final PESignature pesig;
    private final COFFFileHeader coff;
    private final OptionalHeader opt;
    private final SectionTable table;
    private final MSDOSHeader msdos;
    private final File file;
    private final RichHeader rich;

    /**
     * Creates a PEData instance.
     *
     * @param msdos the MSDOS Header
     * @param pesig The signature of the PE
     * @param coff  the COFF File Header
     * @param opt   the Optional Header
     * @param table the Section Table
     * @param file  the file the header information was read from
     */
    public PEData(MSDOSHeader msdos, PESignature pesig, COFFFileHeader coff,
                  OptionalHeader opt, SectionTable table, File file, RichHeader rich) {
        this.pesig = pesig;
        this.coff = coff;
        this.opt = opt;
        this.msdos = msdos;
        this.table = table;
        this.file = file;
        this.rich = rich;
    }

    /**
     * Returns the {@link RichHeader}.
     *
     * @return msdos header
     */
    public Optional<RichHeader> maybeGetRichHeader() {
        return Optional.ofNullable(rich);
    }

    /**
     * Returns the {@link MSDOSHeader}.
     *
     * @return msdos header
     */
    public MSDOSHeader getMSDOSHeader() {
        return msdos;
    }

    /**
     * Returns the {@link PESignature}.
     *
     * @return pe signature
     */
    public PESignature getPESignature() {
        return pesig;
    }

    /**
     * Returns the {@link SectionTable}.
     *
     * @return section table
     */
    public SectionTable getSectionTable() {
        return table;
    }

    /**
     * Returns the {@link COFFFileHeader}.
     *
     * @return coff file header
     */
    public COFFFileHeader getCOFFFileHeader() {
        return coff;
    }

    /**
     * Returns the {@link OptionalHeader}.
     *
     * @return optional header
     */
    public OptionalHeader getOptionalHeader() {
        return opt;
    }

    /**
     * Reads and returns the {@link MSDOSLoadModule}.
     *
     * @return msdos load module
     * @throws IOException if load module can not be read.
     */
    @Beta
    // TODO maybe load with PELoader
    public MSDOSLoadModule readMSDOSLoadModule() throws IOException {
        MSDOSLoadModule module = new MSDOSLoadModule(msdos, file);
        module.read();
        return module;
    }

    /**
     * Returns the file the data belongs to.
     *
     * @return file
     */
    public File getFile() {
        return file;
    }

    /**
     * Returns a description string of all pe headers (that is msdos header,
     * coff file header, optional header and section table).
     *
     * @return description string of all pe headers
     */
    public String getInfo() {
        ReportCreator reporter = new ReportCreator(this);
        return reporter.msdosHeaderReport() + reporter.coffHeaderReport() +
                reporter.optHeaderReport() + reporter.secTableReport();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return getInfo();
    }

    /************* Some extra methods with very common data extraction tasks to improve convenience ***************/
    /**************************************************************************************************************/

    private List<ExportEntry> exports;
    private List<Resource> resources;
    private List<ImportDLL> imports;
    private VersionInfo versionInfo;
    private CodeviewInfo codeviewInfo;
    private List<IcoFile> icons;

    private SignatureScannerManager sigmgr = new SignatureScannerManager(this);

    private CLRSection clrSection;

    private HashMap<Long, String> stringTable;

    private static final int MAX_MANIFEST_SIZE_DEFAULT = 0x5000;
    private int maxManifestSize = MAX_MANIFEST_SIZE_DEFAULT;

    /**
     * Trigger loading all extra data. Subsequent calls to loadXXX will not need to read and parse the PE file again.
     */
    public void loadAll() {
        // alphabethically sorted
        loadClrSection();
        loadCodeViewInfo();
        loadExports();
        loadIcons();
        loadImports();
        loadManifests();
        loadPDBPath();
        loadResources();
        loadStringTable();
        loadVersionInfo();
    }

    /**
     * Tries to load Clr section if not already loaded and returns it as Optional if successful
     * @return empty Optional if no CLR section could be loaded, Optional of CLRSection instance otherwise
     */
    public Optional<CLRSection> loadClrSection() {
        if(clrSection != null) {
            return Optional.of(clrSection);
        }

        SectionLoader loader = new SectionLoader(this);
        try {
            com.google.common.base.Optional<CLRSection> maybeClr = loader.maybeLoadCLRSection();
            if (maybeClr.isPresent() && !maybeClr.get().isEmpty()) {
                this.clrSection = maybeClr.get();
                return Optional.of(clrSection);
            }
        } catch (IOException e) {
            logger.error(e);
            e.printStackTrace();
        }
        return Optional.empty();
    }

    /**
     * Checks if the file is a .NET executable by trying to load .NET metadata
     * @return true iff file is a .NET file
     */
    public boolean isDotNet() {
        return loadClrSection().isPresent();
    }


    /**
     * Loads the CodeviewInfo object of the debug info structure. Reads the PE file to do so unless already loaded.
     *
     * @return Optional of CodeviewInfo
     */
    public Optional<CodeviewInfo> loadCodeViewInfo() {
        if (codeviewInfo != null) {
            return Optional.of(codeviewInfo);
        }
        try {
            com.google.common.base.Optional<DebugSection> sec = new SectionLoader(this).maybeLoadDebugSection();
            if (sec.isPresent()) {
                DebugSection d = sec.get();
                if (d.getCodeView().isPresent()) {
                    this.codeviewInfo = d.getCodeView().get();
                    return Optional.of(codeviewInfo);
                }
            }
        } catch (IOException e) {
            logger.error(e);
            e.printStackTrace();
        }
        return Optional.empty();
    }

    /**
     * Loads the codeview structure and returns the PDB path of it. Reads the PE file to do so unless already loaded.
     * This is included because it is an important IoC for malware. For more detailed info about the CodeviewInfo, use loadCodeviewInfo() or load the debug section.
     *
     * @return String containing the PDB path or empty string if not there
     */
    public String loadPDBPath() {
        if (loadCodeViewInfo().isPresent()) {
            return loadCodeViewInfo().get().filePath();
        }
        return "";
    }

    /**
     * Loads and returns the export entries. Reads the PE file to do so unless already loaded.
     * Returns empty list if no exports available or something goes wrong.
     *
     * @return parsed export entries
     */
    public List<ExportEntry> loadExports() {
        if (exports != null) {
            return exports;
        }
        try {
            com.google.common.base.Optional<ExportSection> maybeEdata = new SectionLoader(this).maybeLoadExportSection();
            if (maybeEdata.isPresent()) {
                ExportSection edata = maybeEdata.get();
                exports = edata.getExportEntries();
                return exports;
            }
        } catch (IOException e) {
            logger.error(e);
            e.printStackTrace();
        }
        return new ArrayList<>();
    }

    /**
     * Check if pe file has any exports. Will load exports if not done already.
     *
     * @return true iff at least one export entry is there
     */
    public boolean hasExports() {
        return loadExports().size() > 0;
    }

    /**
     * Checks if PE file has at least one group icon. Will load resources if not done already.
     *
     * @return true iff at least one group icon found
     */
    public boolean hasGroupIcon() {
        return loadResources().stream().anyMatch(IconParser::isGroupIcon);
    }

    /**
     * Load and return list of icons that are in the PE resources.
     *
     * @return IcoFile list
     */
    public List<IcoFile> loadIcons() {
        if (icons != null) {
            return icons;
        }
        this.icons = IconParser.extractIcons(loadResources(), this);
        return icons;
    }

    /**
     * Obtain a list of imports DLL objects without having to deal with exceptions. Reads the PE file to do so unless already loaded.
     * The import DLL objects contain the referenced symbols.
     *
     * @return list of import DLLs
     */
    public List<ImportDLL> loadImports() {
        if (imports != null) {
            return imports;
        }
        SectionLoader loader = new SectionLoader(this);
        try {
            com.google.common.base.Optional<ImportSection> maybeImports = loader.maybeLoadImportSection();
            if (maybeImports.isPresent() && !maybeImports.get().isEmpty()) {
                ImportSection importSection = maybeImports.get();
                this.imports = importSection.getImports();
                return imports;
            }
        } catch (IOException e) {
            logger.error(e);
            e.printStackTrace();
        }
        return new ArrayList<>();
    }

    /**
     * Check if PE file has any imports. Will load imports if not done already.
     *
     * @return true iff at least one import is there.
     */
    public boolean hasImports() {
        return loadImports().size() > 0;
    }

    /**
     * Loads the manifests if available. Returns empty list if not there. Always reads the PE file to do so.
     * Uses the maximum manifest size that was set via setMaxManifestSize(int maxManifestSize) or loadManifest(int maxManifestSize).
     * The default maximum size is {@value #MAX_MANIFEST_SIZE_DEFAULT}
     *
     * @return manifest info as a string list
     */
    public List<String> loadManifests() {
        return loadManifests(maxManifestSize);
    }

    /**
     * Loads the manifest resources as strings if available. Returns empty list if not there. Always reads the PE file to do so.
     * This will additionally set the manifest size, so that subsequent calls to loadManifest() use the new size.
     *
     * @param maxManifestSize the maximum size in bytes that the manifest is allowed to have
     * @return all manifest files below maxManifestSize as UTF-8 string in a list
     */
    public List<String> loadManifests(int maxManifestSize) {
        this.maxManifestSize = maxManifestSize;
        List<String> manifests = new ArrayList<>();
        try {
            for (Resource r : loadResources()) {
                if (isLegitManifest(r, maxManifestSize)) {
                    manifests.add(loadResourceAsString(r));
                }
            }
        } catch (IOException e) {
            logger.error(e);
            e.printStackTrace();
        }
        return manifests;
    }

    /**
     * If this returns true, the timestamps in the headers are invalid because it is a reproducible build.
     *
     * @return true if REPRO debug directory entry exists
     */
    public boolean isReproBuild() {
        try {
            com.google.common.base.Optional<DebugSection> sec = new SectionLoader(this).maybeLoadDebugSection();
            if (sec.isPresent() && !sec.get().isEmpty()) {
                return sec.get().isReproBuild();
            }
        } catch (IOException e) {
            logger.error(e);
        }
        return false;
    }

    /**
     * Obtain a list of resources without having to deal with exceptions. Reads the PE file to do so unless already loaded.
     *
     * @return List of resources. Empty list if resources do not exist or could not be read
     */
    public List<Resource> loadResources() {
        if (resources != null) {
            return resources;
        }
        try {
            com.google.common.base.Optional<ResourceSection> res = new SectionLoader(this).maybeLoadResourceSection();
            if (res.isPresent() && !res.get().isEmpty()) {
                this.resources = res.get().getResources();
                return resources;
            }
        } catch (IOException e) {
            logger.error(e);
            e.printStackTrace();
        }
        return new ArrayList<>();
    }

    /**
     * Returns a list of all matched signatures.
     *
     * @return
     */
    public List<MatchedSignature> getSignatures() {
       return sigmgr.getAllSignatures();
    }

    /**
     * Returns a list of all matched signatures in the overlay
     *
     * @return
     */
    public List<MatchedSignature> getOverlaySignatures() {
        return sigmgr.getOverlaySignatures();
    }

    /**
     * Returns a list of all matched signatures in the resources
     *
     * @return
     */
    public List<MatchedSignature> getResourceSignatures() {
        return sigmgr.getResourceSignatures();
    }

    /**
     * Returns a list of all matched signatures by PEID
     *
     * @return
     */
    public List<MatchedSignature> getPEIDSignatures() {
        return sigmgr.getPEIDSignatures();
    }

    /**
     * Returns a list of all matched signatures in the MSDOS header or stub
     *
     * @return
     */
    public List<MatchedSignature> getMSDOSSignatures() {
        return sigmgr.getMSDOSSignatures();
    }

    /**
     * Loads the string table (RT_STRING resources) if not already loaded.
     * @return map of string ID and the actual string
     */
    public Map<Long, String> loadStringTable() {
        if(stringTable != null) { return stringTable; }
        stringTable = new HashMap<>();
        int SIZE_LEN = 2;
        List<Resource> strTables = loadResources().stream().filter(res -> res.getType().equals("RT_STRING")).collect(Collectors.toList());
        for (Resource res : strTables) {
            long strId = 0;
            try {
                byte[] bytes = IOUtil.loadBytesOfResource(res, this);
                int currOffset = 0;
                do {
                    long id = 0;
                    if(res.getLevelIDs().get(Level.nameLevel()) instanceof ID) {
                        long resId = ((ID) res.getLevelIDs().get(Level.nameLevel())).id();
                        id = ((resId - 1) * 16) + strId;
                    }
                    int length = (int) ByteArrayUtil.getBytesLongValueSafely(bytes, currOffset, SIZE_LEN);
                    currOffset += SIZE_LEN;
                    strId++;
                    if (length == 0) {
                        continue;
                    }
                    int sizeInBytes = length * 2;
                    if (currOffset + sizeInBytes >= bytes.length) {
                        break;
                    }
                    byte[] stringBytes = Arrays.copyOfRange(bytes, currOffset, currOffset + sizeInBytes);
                    currOffset += sizeInBytes;
                    String str = new String(stringBytes, StandardCharsets.UTF_16LE);
                    stringTable.put(id, str);
                } while (currOffset < bytes.length - SIZE_LEN);

            } catch (IOException e) {
                logger.error("Problem while reading resource bytes: " + e);
            }
        }
        return stringTable;
    }

    /**
     * Check if PE file has Version Info. Will load version info if not done already.
     *
     * @return true iff version info is there.
     */
    public boolean hasVersionInfo() {
        return loadVersionInfo().isPresent();
    }

    /**
     * Loads the VersionInfo resource. Reads the PE file to do so unless already loaded.
     * If several VersionInfo resources are present, only the first one is used.
     *
     * @return version info
     */
    public Optional<VersionInfo> loadVersionInfo() {
        if (versionInfo != null) {
            return Optional.of(versionInfo);
        }
        List<Resource> res = loadResources();
        for (Resource r : res) {
            if (r.getType().equals("RT_VERSION")) {
                this.versionInfo = VersionInfo.apply(r, getFile());
                return Optional.of(versionInfo);
            }
        }
        return Optional.empty();
    }

    /**
     * Set maximum size in bytes for loading the manifest data.
     *
     * @param maxManifestSize the maximum size of the manifest
     *
     */
    public void setMaxManifestSize(int maxManifestSize) {
        this.maxManifestSize = maxManifestSize;
    }

    /**
     * Checks if the given resource is a manifest and if the manifest size is bigger than zero and smaller than the manifestSize threshold
     * @param resource the resource that is supposed to be a manifest
     * @param manifestSize the maximum size of the manifest
     * @return true iff resource is manifest and manifest has data and manifest text is smaller than manifestSize
     */
    private boolean isLegitManifest(Resource resource, int manifestSize) {
        long offset = resource.rawBytesLocation().from();
        long size = resource.rawBytesLocation().size();
        return resource.getType().equals("RT_MANIFEST") && offset > 0 && size > 0 && size <= manifestSize;
    }

    private static String bytesToUTF8(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8).trim();
    }

    /**
     * Loads the bytes of the given resource and returns them as UTF-8 string.
     *
     * @param r resource to read as string
     * @return string with the resource content
     * @throws IOException if loading the resources failed
     */
    // Note: this is not public because it does not belong in the PEData object.
    private String loadResourceAsString(Resource r) throws IOException {
        return bytesToUTF8(IOUtil.loadBytesOfResource(r, this));
    }

}
