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
package com.github.struppigel.parser.optheader;

/**
 * Represents a windows specific field from the optional header.
 * <p>
 * Descriptions are taken from the PECOFF specification.
 * 
 * @author Katja Hahn
 * 
 */
public enum WindowsEntryKey implements OptionalHeaderKey {

    /**
     * The preferred address of the first byte of image when loaded into memory
     */
    IMAGE_BASE,
    /**
     * The alignment (in bytes) of sections when they are loaded into memory.
     */
    SECTION_ALIGNMENT,
    /**
     * The alignment factor (in bytes) that is used to align the raw data of
     * sections in the image file.
     */
    FILE_ALIGNMENT,
    /**
     * The major version number of the required operating system.
     */
    MAJOR_OS_VERSION,
    /**
     * The minor version number of the required operating system.
     */
    MINOR_OS_VERSION,
    /**
     * The major version number of the image.
     */
    MAJOR_IMAGE_VERSION,
    /**
     * The minor version number of the image.
     */
    MINOR_IMAGE_VERSION,
    /**
     * The major version number of the subsystem.
     */
    MAJOR_SUBSYSTEM_VERSION,
    /**
     * The minor version number of the subsystem.
     */
    MINOR_SUBSYSTEM_VERSION,
    /**
     * Reserved, must be zero.
     */
    WIN32_VERSION_VALUE,
    /**
     * The size (in bytes) of the image, including all headers, as the image is
     * loaded in memory.
     */
    SIZE_OF_IMAGE,
    /**
     * The combined size of an MS‑DOS stub, PE header, and section headers
     * rounded up to a multiple of FileAlignment.
     */
    SIZE_OF_HEADERS,
    /**
     * The image file checksum
     */
    CHECKSUM,
    /**
     * The subsystem that is required to run this image.
     */
    SUBSYSTEM,
    /**
     * DLL Characteristics
     */
    DLL_CHARACTERISTICS,
    /**
     * The size of the stack to reserve.
     */
    SIZE_OF_STACK_RESERVE,
    /**
     * The size of the stack to commit.
     */
    SIZE_OF_STACK_COMMIT,
    /**
     * The size of the local heap space to reserve.
     */
    SIZE_OF_HEAP_RESERVE,
    /**
     * The size of the local heap space to commit.
     */
    SIZE_OF_HEAP_COMMIT,
    /**
     * Reserved, must be zero.
     */
    LOADER_FLAGS,
    /**
     * The number of data-directory entries in the remainder of the optional
     * header.
     */
    NUMBER_OF_RVA_AND_SIZES;
}
