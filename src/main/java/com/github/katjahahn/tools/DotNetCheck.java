package com.github.katjahahn.tools;

import com.github.katjahahn.PEData;
import com.github.katjahahn.optheader.DataDirEntry;
import com.github.katjahahn.optheader.DataDirectoryKey;

/**
 * Checks if a file has managed code.
 * 
 * @author Katja Hahn
 *
 */
public class DotNetCheck {
	
	private final PEData data;

	public DotNetCheck(PEData data) {
		this.data = data;
	}
	
	/**
	 * Returns whether a PE has managed code
	 * 
	 * @return true iff the PE has managed code
	 */
	public boolean isDotNetPE() {
		DataDirEntry entry = data.getOptionalHeader().getDataDirEntry(DataDirectoryKey.CLR_RUNTIME_HEADER);
		return entry.virtualAddress != 0;
	}

}
