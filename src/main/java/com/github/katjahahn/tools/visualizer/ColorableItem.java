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

package com.github.katjahahn.tools.visualizer;

/**
 * Keys for colorable items in the visualizer.
 * 
 * @author Karsten Hahn
 * 
 */
public enum ColorableItem {

	/* Header */
	MSDOS_HEADER("MSDOS Header"), COFF_FILE_HEADER("COFF File Header"), OPTIONAL_HEADER(
			"Optional Header"), SECTION_TABLE("Section Table"),
	/* Special Sections and Tables */
	IMPORT_SECTION("Imports"), EXPORT_SECTION("Exports"), DEBUG_SECTION(
			"Debug Info"), RESOURCE_SECTION("Resource Table"), RELOC_SECTION(
			"Relocations"), DELAY_IMPORT_SECTION("Delay Imports"),
	/* Other */
	ENTRY_POINT("Entry Point"), OVERLAY("Overlay"), SECTION_START(""), ANOMALY(
			"Anomaly"),
	/* BytePlot */
	VISIBLE_ASCII("Visible ASCII"), INVISIBLE_ASCII("Invisible ASCII"), NON_ASCII(
			"Non-ASCII"), MAX_BYTE("0xFF"), MIN_BYTE("0x00"),
	/* Entropy*/
	ENTROPY("Entropy"),
	/* VisOverlay */
	VISOVERLAY("Read Chunks");

	private final String description;

	private ColorableItem(String description) {
		this.description = description;
	}

	public String getLegendDescription() {
		return description;
	}
}
