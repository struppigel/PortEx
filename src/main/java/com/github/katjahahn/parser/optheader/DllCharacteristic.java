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
package com.github.katjahahn.parser.optheader;

import java.util.List;

import com.github.katjahahn.parser.Characteristic;
import com.github.katjahahn.parser.FlagUtil;

/**
 * Represents the flags for the DLL Characteristic field of the optional header.
 * 
 * @author Katja Hahn
 * 
 */
public enum DllCharacteristic implements Characteristic {
    /**
     * Reserved, must be zero. Value 0x1
     */
    RESERVED_1("Reserved, must be zero.", 0x1, true, false),
    /**
     * Reserved, must be zero. Value 0x2
     */
    RESERVED_2("Reserved, must be zero.", 0x2, true, false),
    /**
     * Reserved, must be zero. Value 0x4
     */
    RESERVED_4("Reserved, must be zero.", 0x4, true, false),
    /**
     * Reserved, must be zero. Value 0x8
     */
    RESERVED_8("Reserved, must be zero.", 0x8, true, false),
    /**
     * DLL can be relocated at load time.
     */
    IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE(
            "DLL can be relocated at load time.", 0x40),
    /**
     * Code Integrity checks are enforced.
     */
    IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY(
            "Code Integrity checks are enforced.", 0x80),
    /**
     * Image is NX compatible.
     */
    IMAGE_DLL_CHARACTERISTICS_NX_COMPAT("Image is NX compatible.", 0x100),
    /**
     * Isolation aware, but do not isolate the image.
     */
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION(
            "Isolation aware, but do not isolate the image.", 0x200),
    /**
     * Does not use structured exception (SE) handling. No SE handler may be
     * called in this image.
     */
    IMAGE_DLLCHARACTERISTICS_NO_SEH(
            "Does not use structured exception (SE) handling. No SE handler may be called in this image.",
            0x400),
    /**
     * Do not bind the image.
     */
    IMAGE_DLLCHARACTERISTICS_NO_BIND("Do not bind the image.", 0x800),
    /**
     * Reserved, must be zero. Value 0x1000
     */
    RESERVED_1000("Reserved, must be zero.", 0x1000, true, false),
    /**
     * A WDM driver.
     */
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER("A WDM driver.", 0x2000),
    /**
     * Terminal Server aware.
     */
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE("Terminal Server aware.",
            0x8000);

    private boolean deprecated;
    private boolean reserved;
    private String description;
    private long value;

    private DllCharacteristic(String description, long value) {
        this(description, value, false, false);
    }

    private DllCharacteristic(String description, long value,
            boolean reserved, boolean deprecated) {
        this.description = description;
        this.value = value;
        this.reserved = reserved;
        this.deprecated = deprecated;
    }
    
    /**
     * Returns a list of all characteristics, whose flags are set in value
     * 
     * @param value
     * @return list of all characteristics that are set
     */
    public static List<DllCharacteristic> getAllFor(long value) {
        List<DllCharacteristic> list = FlagUtil
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
