package com.github.katjahahn.parser.sections.reloc;

import com.github.katjahahn.parser.Characteristic;

public enum RelocType implements Characteristic {

    /**
     * The base relocation is skipped. This type can be used to pad a block.
     */
    IMAGE_REL_BASED_ABSOLUTE(0, "absolute"),
    /**
     * The base relocation adds the high 16 bits of the difference to the 16-bit
     * field at offset. The 16-bit field represents the high value of a 32-bit
     * word.
     */
    IMAGE_REL_BASED_HIGH(1, "high"),
    /**
     * The base relocation adds the low 16 bits of the difference to the 16-bit
     * field at offset. The 16-bit field represents the low half of a 32-bit
     * word.
     */
    IMAGE_REL_BASED_LOW(2, "low"),
    /**
     * The base relocation applies all 32 bits of the difference to the 32-bit
     * field at offset.
     */
    IMAGE_REL_BASED_HIGHLOW(3, "highlow"),
    /**
     * The base relocation adds the high 16 bits of the difference to the 16-bit
     * field at offset. The 16-bit field represents the high value of a 32-bit
     * word. The low 16 bits of the 32-bit value are stored in the 16-bit word
     * that follows this base relocation. This means that this base relocation
     * occupies two slots.
     */
    IMAGE_REL_BASED_HIGHADJ(4, "highadj"),
    /**
     * For MIPS machine types, the base relocation applies to a MIPS jump
     * instruction.
     */
    IMAGE_REL_BASED_MIPS_JMPADDR(5, "MIPS jump instruction"),
    /**
     * For ARM machine types, the base relocation applies the difference to the
     * 32-bit value encoded in the immediate fields of a contiguous MOVW+MOVT
     * pair in ARM mode at offset.
     */
    IMAGE_REL_BASED_ARM_MOV32A(5, "ARM mov 32 A"),
    /**
     * Reserved, must be zero.
     */
    RESERVED_1(6, "Reserved, must be zero", true),
    /**
     * The base relocation applies the difference to the 32-bit value encoded in
     * the immediate fields of a contiguous MOVW+MOVT pair in Thumb mode at
     * offset.
     */
    IMAGE_REL_BASED_ARM_MOV32T(7, "ARM mov 32 T"),
    /**
     * The base relocation applies to a MIPS16 jump instruction.
     */
    IMAGE_REL_BASED_MIPS_JMPADDR16(9, "MIPS16 jump instruction"),
    /**
     * The base relocation applies the difference to the 64-bit field at offset.
     */
    IMAGE_REL_BASED_DIR64(10, "64-bit field"),
    /**
     * No valid type
     */
    UNKNOWN(-1, "unknown type, corrupt entry");

    private final long value;
    private final String description;
    private final boolean reserved;

    private RelocType(long value, String description) {
        this(value, description, false);
    }

    private RelocType(long value, String description, boolean reserved) {
        this.description = description;
        this.value = value;
        this.reserved = reserved;
    }

    @Override
    public String getDescription() {
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

    @Override
    public long getValue() {
        return value;
    }
    
    public static RelocType getForValue(long value) {
        for(RelocType type : values()) {
            if(type.getValue() == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("No reloc type for value " + value);
    }

}
