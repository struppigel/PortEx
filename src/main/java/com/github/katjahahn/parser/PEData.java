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
package com.github.katjahahn.parser;

import java.io.File;
import java.io.IOException;
import java.util.Optional;

import com.github.katjahahn.parser.coffheader.COFFFileHeader;
import com.github.katjahahn.parser.msdos.MSDOSHeader;
import com.github.katjahahn.parser.msdos.MSDOSLoadModule;
import com.github.katjahahn.parser.optheader.OptionalHeader;
import com.github.katjahahn.parser.sections.SectionTable;
import com.github.katjahahn.tools.ReportCreator;
import com.google.common.annotations.Beta;

/**
 * Container that collects and holds the main information of a PE file.
 * <p>
 * It is constructed by the PELoader and returned to the caller as result from
 * scanning the PE File information.
 * 
 * @author Katja Hahn
 * 
 */
public class PEData {

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
     * @param msdos
     *            the MSDOS Header
     * @param pesig
     *            The signature of the PE
     * @param coff
     *            the COFF File Header
     * @param opt
     *            the Optional Header
     * @param table
     *            the Section Table
     * @param file
     *            the file the header information was read from
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

}
