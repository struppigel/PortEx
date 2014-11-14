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
package com.github.katjahahn.parser.coffheader;

import com.github.katjahahn.parser.Characteristic;

/**
 * Represents the machine the image file can run on.
 * <p>
 * Descriptions are from the PECOFF specification.
 * 
 * @author Katja Hahn
 * 
 */
public enum MachineType implements Characteristic {
    /**
     * The contents of this field are assumed to be applicable to any machine
     * type
     */
    UNKNOWN(
            "The contents of this field are assumed to be applicable to any machine type",
            0x0),
    /**
     * Matsushita AM33
     */
    AM33("Matsushita AM33", 0x1d3),
    /**
     * x64
     */
    AMD64("x64", 0x8664),
    /**
     * ARM little endian
     */
    ARM("ARM little endian", 0x1c0),
    /**
     * ARMv7 (or higher) Thumb mode only
     */
    ARMNT("ARMv7 (or higher) Thumb mode only", 0x1c4),
    /**
     * ARMv8 in 64-bit mod
     */
    ARM64("ARMv8 in 64-bit mod", 0xaa64),
    /**
     * EFI byte code
     */
    EBC("EFI byte code", 0xebc),
    /**
     * Intel 386 or later processors and compatible processors
     */
    I386("Intel 386 or later processors and compatible processors", 0x14c),
    /**
     * Intel Itanium processor family
     */
    IA64("Intel Itanium processor family", 0x200),
    /**
     * Mitsubishi M32R little endian
     */
    M32R("Mitsubishi M32R little endian", 0x9041),
    /**
     * MIPS16
     */
    MIPS16("MIPS16", 0x266),
    /**
     * MIPS with FPU
     */
    MIPSFPU("MIPS with FPU", 0x366),
    /**
     * MIPS16 with FPU
     */
    MIPSFPU16("MIPS16 with FPU", 0x466),
    /**
     * Power PC little endian
     */
    POWERPC("Power PC little endian", 0x1f0),
    /**
     * Power PC with floating point support
     */
    POWERPCFP("Power PC with floating point support", 0x1f1),
    /**
     * MIPS little endian
     */
    R4000("MIPS little endian", 0x166),
    /**
     * Hitachi SH3
     */
    SH3("Hitachi SH3", 0x1a2),
    /**
     * Hitachi SH3 DSP
     */
    SH3DSP("Hitachi SH3 DSP", 0x1a3),
    /**
     * Hitachi SH4
     */
    SH4("Hitachi SH4", 0x1a6),
    /**
     * Hitachi SH5
     */
    SH5("Hitachi SH5", 0x1a8),
    /**
     * ARM or Thumb ("interworking")
     */
    THUMB("ARM or Thumb", 0x1c2),
    /**
     * MIPS little-endian WCE v2
     */
    WCEMIPSV2("MIPS little-endian WCE v2", 0x169);

    private final String description;
    private final long value;

    private MachineType(String description, long value) {
        this.description = description;
        this.value = value;
    }

    /**
     * Returns the machine type for the specified value.
     * 
     * @param value
     *            the value of the machine type
     * @return machine type with value
     */
    public static MachineType getForValue(long value) {
        for (MachineType machine : values()) {
            if (machine.getValue() == value) {
                return machine;
            }
        }
        throw new IllegalArgumentException("couldn't match machine type to value "
                + value);
    }

    /**
     * Returns the key as it is used in the specification.
     * 
     * @return key string as it is in the specification file.
     */
    public String getKey() {
        return "IMAGE_FILE_MACHINE_" + this.toString();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isReserved() {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isDeprecated() {
        return false;
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
