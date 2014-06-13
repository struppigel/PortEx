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
package com.github.katjahahn.tools;

import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.optheader.DataDirEntry;
import com.github.katjahahn.parser.optheader.DataDirectoryKey;
import com.google.common.base.Optional;

/**
 * Checks if a file has managed code.
 * 
 * @author Katja Hahn
 * 
 */
public class DotNetCheck {

    private final PEData data;

    public DotNetCheck(PEData data) {
        this.data = data;
    }

    /**
     * Returns whether a PE has managed code
     * 
     * @return true iff the PE has managed code
     */
    public boolean isDotNetPE() {
        Optional<DataDirEntry> entry = data.getOptionalHeader()
                .maybeGetDataDirEntry(DataDirectoryKey.CLR_RUNTIME_HEADER);
        return entry.isPresent() && entry.get().virtualAddress != 0;
    }

}
