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
package com.github.katjahahn.parser;

import com.google.java.contract.Ensures;

/**
 * Represents a structure in the PE file.
 * 
 * @author Katja Hahn
 *
 */
public interface PEModule {

    /**
     * Returns the file offset for the beginning of the module.
     * 
     * @return file offset for the beginning of the module
     */
    @Ensures("result >= 0")
    public long getOffset();

    /**
     * Returns a description string of the {@link Header}.
     * 
     * @return description string
     */
    @Ensures({"result != null", "result.trim().length() > 0"})
    public String getInfo();
}
