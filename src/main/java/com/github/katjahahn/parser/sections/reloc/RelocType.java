package com.github.katjahahn.parser.sections.reloc;

import com.github.katjahahn.parser.Characteristic;

public enum RelocType implements Characteristic {
    
    IMAGE_REL_BASED_ABSOLUTE("absolute"),
    IMAGE_REL_BASED_HIGH("high"),
    IMAGE_REL_BASED_LOW("low"),
    IMAGE_REL_BASED_HIGHLOW("highlow"),
    IMAGE_REL_BASED_HIGHADJ("highadj"),
    IMAGE_REL_BASED_MIPS_JMPADDR("MIPS jump instruction"),
    IMAGE_REL_BASED_ARM_MOV32A("ARM mov 32 A"),
    RESERVED_1("Reserved, must be zero", true),
    IMAGE_REL_BASED_ARM_MOV32T("ARM mov 32 T"),
    IMAGE_REL_BASED_MIPS_JMPADDR16("MIPS16 jump instruction"),
    IMAGE_REL_BASED_DIR64("64-bit field");
    
    private String description;
    private boolean reserved = false;

    private RelocType(String description) {
        this.description = description;
    }
    
    private RelocType(String description, boolean reserved) {
        this(description);
        this.reserved = reserved;
    }
    
    public String getDescription(){
        return description;
    }
    
    @Override
    public boolean isReserved() {
        return reserved;
    }

    @Override
    public boolean isDeprecated() {
        return false;
    }
    
   
}
