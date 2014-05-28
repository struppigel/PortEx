/*******************************************************************************
 * Copyright 2014 Katja Hahn
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
package com.github.katjahahn;

import static com.github.katjahahn.PEModule.*;

import java.io.File;
import java.io.IOException;

import com.github.katjahahn.coffheader.COFFFileHeader;
import com.github.katjahahn.msdos.MSDOSHeader;
import com.github.katjahahn.msdos.MSDOSLoadModule;
import com.github.katjahahn.optheader.OptionalHeader;
import com.github.katjahahn.sections.SectionTable;

/**
 * Container that collects and holds the main information of a PE file. It is
 * usually constructed by the PELoader and returned to the caller as result from
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

	/**
	 * @constructor Creates a PEData instance.
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
	 */
	public PEData(MSDOSHeader msdos, PESignature pesig, COFFFileHeader coff,
			OptionalHeader opt, SectionTable table, File file) {
		this.pesig = pesig;
		this.coff = coff;
		this.opt = opt;
		this.msdos = msdos;
		this.table = table;
		this.file = file;
	}

	/**
	 * Returns the {@link MSDOSHeader}
	 * 
	 * @return msdos header
	 */
	public MSDOSHeader getMSDOSHeader() {
		return msdos;
	}

	/**
	 * Returns the {@link PESignature}
	 * 
	 * @return pe signature
	 */
	public PESignature getPESignature() {
		return pesig;
	}

	/**
	 * Returns the {@link SectionTable}
	 * 
	 * @return section table
	 */
	public SectionTable getSectionTable() {
		return table;
	}

	/**
	 * Returns the {@link COFFFileHeader}
	 * 
	 * @return coff file header
	 */
	public COFFFileHeader getCOFFFileHeader() {
		return coff;
	}

	/**
	 * Returns the {@link OptionalHeader}
	 * 
	 * @return optional header
	 */
	public OptionalHeader getOptionalHeader() {
		return opt;
	}

	/**
	 * Reads and returns the {@link MSDOSLoadModule}
	 * 
	 * @return msdos load module
	 * @throws IOException
	 */
	// TODO maybe load with PELoader
	public MSDOSLoadModule readMSDOSLoadModule() throws IOException {
		MSDOSLoadModule module = new MSDOSLoadModule(msdos, file);
		module.read();
		return module;
	}

	/**
	 * Returns the file the data belongs to
	 * 
	 * @return file
	 */
	public File getFile() {
		return file;
	}

	/**
	 * Returns a description string of all pe headers (that is msdos header,
	 * pesignature, coff file header, optional header and section table)
	 * 
	 * @return description string of all pe headers
	 */
	public String getInfo() {
		return msdos.getInfo() + NL + pesig.getInfo() + NL + coff.getInfo()
				+ NL + opt.getInfo() + NL + table.getInfo();
	}

	@Override
	public String toString() {
		return getInfo();
	}

}
