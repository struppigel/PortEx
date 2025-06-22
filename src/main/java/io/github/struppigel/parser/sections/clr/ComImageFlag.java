package io.github.struppigel.parser.sections.clr;

import io.github.struppigel.parser.Characteristic;
import io.github.struppigel.parser.FlagUtil;

import java.util.List;

public enum ComImageFlag implements Characteristic {
    COMIMAGE_FLAGS_ILONLY("IL only. Shall be 1", 0x00000001),
    COMIMAGE_FLAGS_32BITREQUIRED("Image can only be loaded into 32-bit process", 0x00000002),
    COMIMAGE_FLAGS_STRONGNAMESIGNED("Image has a strong name signature", 0x00000008),
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT("Native entrypoint, shall be 0", 0x00000010),
    COMIMAGE_FLAGS_TRACKDEBUGDATA("Track debug data. Should be 0", 0x00010000);

    private final String description;
    private final long value;

    ComImageFlag(String description, long value) {
        this.description = description;
        this.value = value;
    }

    /**
     * Returns a list of all characteristics, whose flags are set in value
     *
     * @param value the flag value as long
     * @return list of all characteristics that are set
     */
    public static List<ComImageFlag> getAllFor(long value) {
        return FlagUtil
                .getAllMatching(value, values());
    }

    /**
     * Indicates whether the flag is reserved for future use.
     *
     * @return true iff reserved
     */
    @Override
    public boolean isReserved() {
        return false;
    }

    /**
     * Indicates whether the flag is deprecated.
     *
     * @return true iff deprecated
     */
    @Override
    public boolean isDeprecated() {
        return false;
    }

    /**
     * Returns the description of the characteristic.
     *
     * @return description string
     */
    @Override
    public String getDescription() {
        return description;
    }

    /**
     * Returns the value or bitmask of this characteristic.
     *
     * @return value
     */
    @Override
    public long getValue() {
        return value;
    }
}
