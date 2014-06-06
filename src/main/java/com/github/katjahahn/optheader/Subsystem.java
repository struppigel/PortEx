package com.github.katjahahn.optheader;

import com.github.katjahahn.Characteristic;

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
    IMAGE_SYSTEM_UNKNOWN,
    /**
     * Device drivers and native Windows processes
     */
    IMAGE_SUBSYSTEM_NATIVE,
    /**
     * The Windows graphical user interface (GUI) subsystem
     */
    IMAGE_SUBSYSTEM_WINDOWS_GUI,
    /**
     * The Windows character subsystem
     */
    IMAGE_SUBSYSTEM_WINDOWS_CUI,
    /**
     * The Posix character subsystem
     */
    IMAGE_SUBSYSTEM_POSIX_CUI,
    /**
     * Windows CE
     */
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI,
    /**
     * An Extensible Firmware Interface (EFI) application
     */
    IMAGE_SUBSYSTEM_EFI_APPLICATION,
    /**
     * An EFI driver with boot services
     */
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
    /**
     * An EFI driver with run-time services
     */
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER,
    /**
     * An EFI ROM image
     */
    IMAGE_SUBSYSTEM_EFI_ROM,
    /**
     * XBOX
     */
    IMAGE_SUBSYSTEM_XBOX;

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
}
