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

/**
 * Represents characteristic flags used by the PE format. These include, among
 * others, file characteristics, dll characteristics, subsystem, machinetype,
 * reloctypes.
 * 
 * @author Katja Hahn
 * 
 */
public interface Characteristic {

    /**
     * Indicates whether the flag is reserved for future use.
     * 
     * @return true iff reserved
     */
    boolean isReserved();

    /**
     * Indicates whether the flag is deprecated.
     * 
     * @return true iff deprecated
     */
    boolean isDeprecated();
    
    /**
     * Returns the description of the characteristic.
     * 
     * @return description string
     */
    String getDescription();

    /**
     * Returns the value or bitmask of this characteristic.
     * 
     * @return value
     */
    long getValue();

}
