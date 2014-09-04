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
    UNKNOWN,
    /**
     * COFF debug information
     */
    COFF,
    /**
     * Visual C++ debug information
     */
    CODEVIEW,
    /**
     * Frame Pointer Omission (FPO) information
     */
    FPO,
    /**
     * Location of DBG file
     */
    MISC,
    /**
     * Copy of .pdata section
     */
    EXCEPTION,
    /**
     * Fixup (reserved)
     */
    FIXUP(true, false),
    /**
     * Mapping from an RVA in image to an RVA in source image
     */
    SRC,
    /**
     * Mapping from an RVA in source image to an RVA in image
     */
    OMAP_FROM_SRC,
    /**
     * Borland (reserved)
     */
    BORLAND(true, false),
    /**
     * Reserved
     */
    RESERVED10(true, false),
    /**
     * CLSID (reserved)
     */
    CLSID(true, false);
    
    private boolean reserved;
    private boolean deprecated;

    private DebugType(){
        this(false, false);
    }
    
    private DebugType(boolean reserved, boolean deprecated) {
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
}
