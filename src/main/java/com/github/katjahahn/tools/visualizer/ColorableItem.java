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

package com.github.katjahahn.tools.visualizer;

/**
 * Keys for colorable items in the visualizer.
 * 
 * @author Katja Hahn
 *
 */
public enum ColorableItem {

    /* Header */
    MSDOS_HEADER, COFF_FILE_HEADER, OPTIONAL_HEADER, SECTION_TABLE,
    /* Special Sections and Tables */
    IMPORT_SECTION, EXPORT_SECTION, DEBUG_SECTION, RESOURCE_SECTION, RELOC_SECTION,
    DELAY_IMPORT_SECTION,
    /* Other */
    ENTRY_POINT, OVERLAY, SECTION_START, ANOMALY;

    public String getLegendDescription() {
        return this.toString();
    }
}
