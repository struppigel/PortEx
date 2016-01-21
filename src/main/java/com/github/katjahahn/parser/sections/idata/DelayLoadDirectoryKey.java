/**
 * *****************************************************************************
 * Copyright 2016 Katja Hahn
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
 * ****************************************************************************
 */

package com.github.katjahahn.parser.sections.idata;

import com.github.katjahahn.parser.HeaderKey;

/**
 * Represents keys for the delay-load directory table.
 * <p>
 * Descriptions are taken from the PE/COFF specification.
 * 
 * @author Katja Hahn
 * 
 */
public enum DelayLoadDirectoryKey implements HeaderKey {
    /**
     * Must be zero
     */
    ATTRIBUTES,
    /**
     * The RVA of the name of the DLL to be loaded. The name resides in the
     * read-only data section of the image
     */
    NAME,
    /**
     * The RVA of the module handle (in the data section of the image) of the
     * DLL to be delay-loaded. It is used for storage by the routine that is
     * supplied to manage delay-loading.
     */
    MODULE_HANDLE,
    /**
     * The RVA of the delay-load import address table.
     */
    DELAY_IAT,
    /**
     * The RVA of the delay-load name table, which contains the names of the
     * imports that might need to be loaded. This matches the layout of the
     * import name table.
     */
    DELAY_IMPORT_NAME_TABLE,
    /**
     * The RVA of the bound delay-load address table, if it exists.
     */
    BOUND_DELAY_IMPORT_TABLE,
    /**
     * The RVA of the unload delay-load address table, if it exists. This is an
     * exact copy of the delay import address table. If the caller unloads the
     * DLL, this table should be copied back over the delay import address table
     * so that subsequent calls to the DLL continue to use the thunking
     * mechanism correctly.
     */
    UNLOAD_DELAY_IMPORT_TABLE,
    /**
     * The timestamp of the DLL to which this image has been bound.
     */
    TIME_STAMP;
}
