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
package com.github.katjahahn.parser.sections;

import com.github.katjahahn.parser.Characteristic;

/**
 * Represents the attributes of a section.
 * 
 * @author Katja Hahn
 * 
 */
public enum SectionCharacteristic implements Characteristic {
    /**
     * Reserved for future use.
     */
    RESERVED_0(0x00000000, "Reserved 0", "Reserved for future use.", true,
            false),
    /**
     * Reserved for future use.
     */
    RESERVED_1(0x00000001, "Reserved 1", "Reserved for future use.", true,
            false),
    /**
     * Reserved for future use.
     */
    RESERVED_2(0x00000002, "Reserved 2", "Reserved for future use.", true,
            false),
    /**
     * Reserved for future use.
     */
    RESERVED_4(0x00000004, "Reserved 4", "Reserved for future use.", true,
            false),
    /**
     * The section should not be padded to the next boundary.
     */
    IMAGE_SCN_TYPE_NO_PAD(
            0x00000008,
            "No Pad",
            "The section should not be padded to the next boundary. DEPRECATED",
            false, true),
    /**
     * Reserved for future use.
     */
    RESERVED_10(0x00000010, "Reserved 10", "Reserved for future use.", true,
            false),
    /**
     * The section contains executable code.
     */
    IMAGE_SCN_CNT_CODE(0x00000020, "Code",
            "The section contains executable code."),
    /**
     * The section contains initialized data.
     */
    IMAGE_SCN_CNT_INITIALIZED_DATA(0x00000040, "Initialized Data",
            "The section contains initialized data."),
    /**
     * The section contains uninitialized data.
     */
    IMAGE_SCN_CNT_UNINITIALIZED_DATA(0x00000080, "Uninitialized Data",
            "The section contains uninitialized data."),
    /**
     * Reserved for future use.
     */
    IMAGE_SCN_LNK_OTHER(0x00000100, "Lnk Other (reserved)",
            "Reserved for future use.", true, false),
    /**
     * The section contains comments or other information. Valid for object
     * files only.
     */
    IMAGE_SCN_LNK_INFO(
            0x00000200,
            "Lnk Info",
            "The section contains comments or other information. Valid for object files only."),
    /**
     * Reserved for future use.
     */
    RESERVED_400(0x00000400, "Reserved 400", "Reserved for future use.", true,
            false),
    /**
     * The section will not become part of the image. Valid for object files
     * only.
     */
    IMAGE_SCN_LNK_REMOVE(0x00000800, "Lnk Remove",
            "The section will not become part of the image. Valid for object files only."),
    /**
     * The section contains COMDAT data.
     */
    IMAGE_SCN_LNK_COMDAT(0x00001000, "COMDAT data",
            "The section contains COMDAT data."),
    /**
     * The section contains data referenced through the global pointer (GP).
     */
    IMAGE_SCN_GPREL(0x00008000, "Global Pointer Ref.",
            "The section contains data referenced through the global pointer (GP)."),
    /**
     * Reserved for future use.
     */
    IMAGE_SCN_MEM_PURGEABLE(0x00020000, "Purgeable (reserved)",
            "Reserved for future use.", true, false),
    /**
     * For ARM machine types, the section contains Thumb code. Reserved for
     * future use with other machine types.
     */
    IMAGE_SCN_MEM_16BIT(
            0x00020000,
            "Mem 16 Bit (reserved)",
            "For ARM machine types, the section contains Thumb code. Reserved for future use with other machine types.",
            true, false),
    /**
     * Reserved for future use.
     */
    IMAGE_SCN_MEM_LOCKED(0x00040000, "Mem Locked (reserved)",
            "Reserved for future use.", true, false),
    /**
     * Reserved for future use.
     */
    IMAGE_SCN_MEM_PRELOAD(0x00080000, "Preload (reserved)",
            "Reserved for future use.", true, false),
    /**
     * Align data on a 1-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_1BYTES(0x00100000, "Align 1 Byte",
            "Align data on a 1-byte boundary. Valid only for object files."),
    /**
     * Align data on a 2-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_2BYTES(0x00200000, "Align 2 Bytes",
            "Align data on a 2-byte boundary. Valid only for object files."),
    /**
     * Align data on a 4-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_4BYTES(0x00300000, "Align 4 Bytes",
            "Align data on a 4-byte boundary. Valid only for object files."),
    /**
     * Align data on a 8-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_8BYTES(0x00400000, "Align 8 Bytes",
            "Align data on a 8-byte boundary. Valid only for object files."),
    /**
     * Align data on a 16-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_16BYTES(0x00500000, "Align 16 Bytes",
            "Align data on a 16-byte boundary. Valid only for object files."),
    /**
     * Align data on a 32-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_32BYTES(0x00600000, "Align 32 Bytes",
            "Align data on a 32-byte boundary. Valid only for object files."),
    /**
     * Align data on a 64-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_64BYTES(0x00700000, "Align 64 Bytes",
            "Align data on a 64-byte boundary. Valid only for object files."),
    /**
     * Align data on a 128-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_128BYTES(0x00800000, "Align 128 Bytes",
            "Align data on a 128-byte boundary. Valid only for object files."),
    /**
     * Align data on a 256-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_256BYTES(0x00900000, "Align 256 Bytes",
            "Align data on a 256-byte boundary. Valid only for object files."),
    /**
     * Align data on a 512-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_512BYTES(0x00A00000, "Align 512 Bytes",
            "Align data on a 512-byte boundary. Valid only for object files."),
    /**
     * Align data on a 1024-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_1024BYTES(0x00B00000, "Align 1024 Bytes",
            "Align data on a 1024-byte boundary. Valid only for object files."),
    /**
     * Align data on a 2048-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_2048BYTES(0x00C00000, "Align 2048 Bytes",
            "Align data on a 2048-byte boundary. Valid only for object files."),
    /**
     * Align data on a 4096-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_4096BYTES(0x00D00000, "Align 4096 Bytes",
            "Align data on a 4096-byte boundary. Valid only for object files."),
    /**
     * Align data on a 8192-byte boundary. Valid only for object files.
     */
    IMAGE_SCN_ALIGN_8192BYTES(0x00E00000, "Align 8192 Bytes",
            "Align data on a 8192-byte boundary. Valid only for object files."),
    /**
     * The section contains extended relocations.
     */
    IMAGE_SCN_LNK_NRELOC_OVFL(0x01000000, "Extended Relocations",
            "The section contains extended relocations."),
    /**
     * The section can be discarded as needed.
     */
    IMAGE_SCN_MEM_DISCARDABLE(0x02000000, "Discardable",
            "The section can be discarded as needed."),
    /**
     * The section cannot be cached.
     */
    IMAGE_SCN_MEM_NOT_CACHED(0x04000000, "Not Cached",
            "The section cannot be cached."), IMAGE_SCN_MEM_NOT_PAGED(
            0x08000000, "Not Pageable", "The section is not pageable."), IMAGE_SCN_MEM_SHARED(
            0x10000000, "Shared", "The section can be shared in memory."), IMAGE_SCN_MEM_EXECUTE(
            0x20000000, "Execute", "The section can be executed as code."), IMAGE_SCN_MEM_READ(
            0x40000000, "Read", "The section can be read."), IMAGE_SCN_MEM_WRITE(
            0x80000000, "Write", "The section can be written to.");

    private final String shortName;
    private final String description;
    private final boolean deprecated;
    private final boolean reserved;
    private final long value;

    private SectionCharacteristic(long value, String shortName,
            String description) {
        this(value, shortName, description, false, false);
    }

    private SectionCharacteristic(long value, String shortName,
            String description, boolean reserved, boolean deprecated) {
        this.value = value;
        this.shortName = shortName;
        this.description = description;
        this.reserved = reserved;
        this.deprecated = deprecated;
    }

    public String shortName() {
        return shortName;
    }

    /**
     * Returns the description of the section characteristic.
     * 
     * @return description
     */
    public String getDescription() {
        return description;
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
    public long getValue() {
        return value;
    }
}
