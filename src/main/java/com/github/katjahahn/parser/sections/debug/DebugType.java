package com.github.katjahahn.parser.sections.debug;

import com.github.katjahahn.parser.Characteristic;

/**
 * Represents the type of debug information.
 * 
 * @author Katja Hahn
 * 
 */
public enum DebugType implements Characteristic {
    /**
     * Unkown value
     */
    UNKNOWN(0, "Unknown value"),
    /**
     * COFF debug information
     */
    COFF(1, "COFF debug information"),
    /**
     * Visual C++ debug information
     */
    CODEVIEW(2, "Visual C++ debug information"),
    /**
     * Frame Pointer Omission (FPO) information
     */
    FPO(3, "Frame Pointer Omission (FPO) information"),
    /**
     * Location of DBG file
     */
    MISC(4, "Location of DBG file"),
    /**
     * Copy of .pdata section
     */
    EXCEPTION(5, "Copy of .pdata section"),
    /**
     * Fixup (reserved)
     */
    FIXUP(6, "Fixup (reserved)", true, false),
    /**
     * Mapping from an RVA in image to an RVA in source image
     */
    SRC(7, "Mapping from an RVA in image to an RVA in source image"),
    /**
     * Mapping from an RVA in source image to an RVA in image
     */
    OMAP_FROM_SRC(8, "Mapping from an RVA in source image to an RVA in image"),
    /**
     * Borland (reserved)
     */
    BORLAND(9, "Borland (reserved)", true, false),
    /**
     * Reserved
     */
    RESERVED10(10, "Reserved 10", true, false),
    /**
     * CLSID (reserved)
     */
    CLSID(11, "CLSID (reserved)", true, false);

    private final String description;
    private final long value;
    private final boolean reserved;
    private final boolean deprecated;

    private DebugType(long value, String description) {
        this(value, description, false, false);
    }

    private DebugType(long value, String description, boolean reserved,
            boolean deprecated) {
        this.value = value;
        this.description = description;
        this.reserved = reserved;
        this.deprecated = deprecated;
    }

    @Override
    public boolean isReserved() {
        return reserved;
    }

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
    
    public static DebugType getForValue(long value) {
        for(DebugType type : values()) {
            if(type.getValue() == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("No debug type for value " + value);
    }
}
