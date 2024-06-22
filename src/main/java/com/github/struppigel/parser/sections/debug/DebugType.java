package com.github.struppigel.parser.sections.debug;

import com.github.struppigel.parser.Characteristic;
import com.github.struppigel.parser.Characteristic;

/**
 * Represents the type of debug information.
 * 
 * @author Katja Hahn
 * 
 */
public enum DebugType implements Characteristic {
    /**
     * Unknown value
     */
    UNKNOWN(0, "An unknown value that is ignored by all tools."),
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
     * Reserved 10
     */
    RESERVED10(10, "Reserved 10", true, false),
    /**
     * CLSID (reserved)
     */
    CLSID(11, "CLSID (reserved)", true, false),
    /**
     * CLSID (reserved)
     */
    VC_FEATURE(12, "VC Feature", false, false),
    /**
     * POGO
     */
    POGO(13,"POGO", false, false),
    /**
     * ILTCG
     */
    ILTCG(14,"ILTCG", false, false),
    /**
     * MPX
     */
    MPX(15,"MPX", false, false),
    /**
     * Repro, PE determinism or reproducibility
     */
    REPRO(16,"Repro, PE determinism or reproducibility", false, false),

    /**
     * Debugging information is embedded in the PE file at location specified by PointerToRawData.
     */
    UNDEFINED_DEBUG_INFO(17, "Debugging information is embedded in the PE file at location specified by PointerToRawData. ", false ,false),

    /**
     * Stores crypto hash for the content of the symbol file used to build the PE/COFF file.
     */
    CRYPTOHASH(19, "Stores crypto hash for the content of the symbol file used to build the PE/COFF file.", false ,false),
    /**
     * Extended DLL characteristics bits
     */
    EX_DLLCHARACTERISTICS(20,"Extended DLL characteristics bits", false, false);

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
