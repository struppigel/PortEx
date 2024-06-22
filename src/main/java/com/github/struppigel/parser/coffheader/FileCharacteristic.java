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
package com.github.struppigel.parser.coffheader;

import com.github.struppigel.parser.Characteristic;
import com.github.struppigel.parser.FlagUtil;
import com.github.struppigel.parser.Characteristic;
import com.github.struppigel.parser.FlagUtil;

import java.util.List;

/**
 * Represents the flags that indicate the attributes of the file.
 * <p>
 * Descriptions taken from the PECOFF specification.
 * 
 * @author Karsten Hahn
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
    IMAGE_FILE_RELOCS_STRIPPED(
            "Image only, Windows CE, and Windows NT and later.", 0x1),
    /**
     * This indicates that the image file is valid and can be run. If this flag
     * is not set, it indicates a linker error.
     * 
     */
    IMAGE_FILE_EXECUTABLE_IMAGE("Image only.", 0x2),
    /**
     * COFF line numbers have been removed. This flag is deprecated and should
     * be zero.
     * 
     */
    IMAGE_FILE_LINE_NUMS_STRIPPED(
            "COFF line numbers have been removed. DEPRECATED", 0x4, false, true),
    /**
     * COFF symbol table entries for local symbols have been removed. This flag
     * is deprecated and should be zero.
     */
    IMAGE_FILE_LOCAL_SYMS_STRIPPED(
            "COFF symbol table entries for local symbols have been removed. DEPRECATED",
            0x8, false, true),
    /**
     * Obsolete. Aggressively trim working set. This flag is deprecated for
     * Windows 2000 and later and must be zero.
     */
    IMAGE_FILE_AGGRESSIVE_WS_TRIM(
            "Aggressively trim working set. DEPRECATED for Windows 2000 and later.",
            0x10, false, true),
    /**
     * Application can handle > 2‑GB addresses.
     */
    IMAGE_FILE_LARGE_ADDRESS_AWARE("Application can handle > 2 GB addresses.",
            0x20),
    /**
     * This flag with value 0x40 is reserved for future use.
     */
    RESERVED_40("Value 40, reserved for future use.", 0x40, true, false),
    /**
     * Little endian: the least significant bit (LSB) precedes the most
     * significant bit (MSB) in memory. This flag is deprecated and should be
     * zero.
     */
    IMAGE_FILE_BYTES_REVERSED_LO("little endian. DEPRECATED", 0x80, false, true),
    /**
     * Machine is based on a 32-bit-word architecture.
     */
    IMAGE_FILE_32BIT_MACHINE("Machine is based on a 32-bit-word architecture.",
            0x100),
    /**
     * Debugging information is removed from the image file.
     */
    IMAGE_FILE_DEBUG_STRIPPED("Debugging is removed from the image file.",
            0x200),
    /**
     * If the image is on removable media, fully load it and copy it to the swap
     * file.
     */
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP(
            "If the image is on removable media, fully load it and copy it to the swap file.",
            0x400),
    /**
     * If the image is on network media, fully load it and copy it to the swap
     * file.
     */
    IMAGE_FILE_NET_RUN_FROM_SWAP(
            "If the image is on network media, fully load it and copy it to the swap file.",
            0x800),
    /**
     * The image file is a system file, not a user program.
     */
    IMAGE_FILE_SYSTEM("The image file is a system file, not a user program.",
            0x1000),
    /**
     * The image file is a dynamic-link library (DLL). Such files are considered
     * executable files for almost all purposes, although they cannot be
     * directly run.
     */
    IMAGE_FILE_DLL(
            "The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.",
            0x2000),
    /**
     * The file should be run only on a uniprocessor machine.
     */
    IMAGE_FILE_UP_SYSTEM_ONLY(
            "The file should be run only on a uniprocessor machine.", 0x4000),
    /**
     * Big endian: the MSB precedes the LSB in memory. This flag is deprecated
     * and should be zero.
     */
    IMAGE_FILE_BYTES_REVERSED_HI("big endian. DEPRECATED", 0x8000, false, true);

    private boolean deprecated;
    private boolean reserved;
    private String description;
    private long value;

    private FileCharacteristic(String description, long value) {
        this(description, value, false, false);
    }

    private FileCharacteristic(String description, long value,
            boolean reserved, boolean deprecated) {
        this.reserved = reserved;
        this.deprecated = deprecated;
        this.description = description;
        this.value = value;
    }

    /**
     * Returns a list of all characteristics, whose flags are set in value
     * 
     * @param value
     * @return list of all characteristics that are set
     */
    public static List<FileCharacteristic> getAllFor(long value) {
        List<FileCharacteristic> list = FlagUtil
                .getAllMatching(value, values());
        return list;
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

    @Override
    public String getDescription() {
        return description;
    }

    @Override
    public long getValue() {
        return value;
    }
}
