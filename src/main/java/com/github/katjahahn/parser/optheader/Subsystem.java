package com.github.katjahahn.parser.optheader;

import com.github.katjahahn.parser.Characteristic;

/**
 * Represents the subsystem that is required to run this image.
 * <p>
 * Descriptions are from the PECOFF specification.
 * 
 * @author Katja Hahn
 * 
 */
public enum Subsystem implements Characteristic {
    /**
     * An unknown subsystem
     */
    IMAGE_SUBSYSTEM_UNKNOWN("unknown subsystem", 0),
    /**
     * Device drivers and native Windows processes
     */
    IMAGE_SUBSYSTEM_NATIVE("Device drivers and native Windows processes", 1),
    /**
     * The Windows graphical user interface (GUI) subsystem
     */
    IMAGE_SUBSYSTEM_WINDOWS_GUI(
            "The Windows graphical user interface (GUI) subsystem", 2),
    /**
     * The Windows character subsystem
     */
    IMAGE_SUBSYSTEM_WINDOWS_CUI("The Windows character subsystem", 3),
    /**
     * OS/2 CUI subsystem
     */
    IMAGE_SUBSYSTEM_OS2_CUI("OS/2 CUI subsystem", 5),
    /**
     * The Posix character subsystem
     */
    IMAGE_SUBSYSTEM_POSIX_CUI("The POSIX CUI subsystem", 7),
    /**
     * Windows CE
     */
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI("Windows CE system", 9),
    /**
     * An Extensible Firmware Interface (EFI) application
     */
    IMAGE_SUBSYSTEM_EFI_APPLICATION(
            "An Extensible Firmware Interface (EFI) application", 10),
    /**
     * An EFI driver with boot services
     */
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER("An EFI driver with boot services",
            11),
    /**
     * An EFI driver with run-time services
     */
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER("An EFI driver with run-time services",
            12),
    /**
     * An EFI ROM image
     */
    IMAGE_SUBSYSTEM_EFI_ROM("An EFI ROM image", 13),
    /**
     * XBOX
     */
    IMAGE_SUBSYSTEM_XBOX("XBOX system", 14),
    /**
     * Boot application
     */
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION("Boot application", 16);
    
    private final String description;
    private final long value;
    
    private Subsystem(String description, long value) {
        this.description = description;
        this.value = value;
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

    public static Subsystem getForValue(long value) {
        for(Subsystem subsystem : values()) {
            if(subsystem.getValue() == value) {
                return subsystem;
            }
        }
        throw new IllegalArgumentException("No subsystem for value " + value);
    }
}
