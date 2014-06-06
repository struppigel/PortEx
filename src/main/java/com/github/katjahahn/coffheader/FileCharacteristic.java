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
package com.github.katjahahn.coffheader;

import com.github.katjahahn.Characteristic;

/**
 * Represents the flags that indicate the attributes of the file.
 * <p>
 * Descriptions taken from the PECOFF specification.
 * 
 * @author Katja Hahn
 * 
 */
public enum FileCharacteristic implements Characteristic {

	/**
	 * Windows CE, and Windows NT® and later. This indicates that the file does
	 * not contain base relocations and must therefore be loaded at its
	 * preferred base address. If the base address is not available, the loader
	 * reports an error. The default behavior of the linker is to strip base
	 * relocations from executable (EXE) files.
	 */
	IMAGE_FILE_RELOCS_STRIPPED,
	/**
	 * This indicates that the image file is valid and can be run. If this flag
	 * is not set, it indicates a linker error.
	 * 
	 */
	IMAGE_FILE_EXECUTABLE_IMAGE,
	/**
	 * COFF line numbers have been removed. This flag is deprecated and should
	 * be zero.
	 * 
	 */
	IMAGE_FILE_LINE_NUMS_STRIPPED(false, true),
	/**
	 * COFF symbol table entries for local symbols have been removed. This flag
	 * is deprecated and should be zero.
	 */
	IMAGE_FILE_LOCAL_SYMS_STRIPPED(false, true),
	/**
	 * Obsolete. Aggressively trim working set. This flag is deprecated for
	 * Windows 2000 and later and must be zero.
	 */
	IMAGE_FILE_AGGRESSIVE_WS_TRIM(false, true),
	/**
	 * Application can handle > 2‑GB addresses.
	 */
	IMAGE_FILE_LARGE_ADDRESS_AWARE,
	/**
	 * This flag with value 0x40 is reserved for future use.
	 */
	RESERVED_40(true, false), // TODO include to anomaly detection
	/**
	 * Little endian: the least significant bit (LSB) precedes the most
	 * significant bit (MSB) in memory. This flag is deprecated and should be
	 * zero.
	 */
	IMAGE_FILE_BYTES_REVERSED_LO(false, true),
	/**
	 * Machine is based on a 32-bit-word architecture
	 */
	IMAGE_FILE_32BIT_MACHINE,
	/**
	 * Debugging information is removed from the image file.
	 */
	IMAGE_FILE_DEBUG_STRIPPED,
	/**
	 * If the image is on removable media, fully load it and copy it to the swap
	 * file.
	 */
	IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
	/**
	 * If the image is on network media, fully load it and copy it to the swap
	 * file.
	 */
	IMAGE_FILE_NET_RUN_FROM_SWAP,
	/**
	 * The image file is a system file, not a user program.
	 */
	IMAGE_FILE_SYSTEM,
	/**
	 * The image file is a dynamic-link library (DLL). Such files are considered
	 * executable files for almost all purposes, although they cannot be
	 * directly run.
	 */
	IMAGE_FILE_DLL,
	/**
	 * The file should be run only on a uniprocessor machine.
	 */
	IMAGE_FILE_UP_SYSTEM_ONLY,
	/**
	 * Big endian: the MSB precedes the LSB in memory. This flag is deprecated
	 * and should be zero.
	 */
	IMAGE_FILE_BYTES_REVERSED_HI(false, true);

	private boolean deprecated;
	private boolean reserved;

	private FileCharacteristic() {
		this.deprecated = false;
		this.reserved = false;
	}

	private FileCharacteristic(boolean reserved, boolean deprecated) {
		this.reserved = reserved;
		this.deprecated = deprecated;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isReserved() {
		return reserved;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isDeprecated() {
		return deprecated;
	}
}
