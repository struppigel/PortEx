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
package com.github.katjahahn.parser.sections;

import com.github.katjahahn.parser.PEModule;
import com.github.katjahahn.parser.PhysicalLocation;

import java.util.List;

/**
 * Represents a special section, whose format is described in the PECOFF
 * 
 * @author Katja Hahn
 *
 */
public interface SpecialSection extends PEModule {

    /**
     * Returns whether the special section has no entries.
     * 
     * @return true if no entries, false otherwise
     */
    boolean isEmpty();
    
    /**
     * Returns a list of physical address ranges this special section is parsed from.
     * 
     * @return list of locations
     */
    List<PhysicalLocation> getPhysicalLocations();

}
