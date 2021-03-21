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

import java.util.ArrayList;
import java.util.List;

/**
 * Utility methods for flag-related operations.
 * 
 * @author Karsten Hahn
 *
 */
public abstract class FlagUtil {

    /**
     * Returns a list of all flags, which are set in the value
     * 
     * @param value
     * @return list of all flags that are set
     */
    public static <T extends Characteristic> List<T> getAllMatching(long value,
            T[] flags) {
        List<T> list = new ArrayList<>();
        // check every characteristic if it fits
        for (T ch : flags) {
            // read mask
            long mask = ch.getValue();
            // use mask to check if flag is set
            if ((value & mask) != 0) {
                list.add(ch);
            }
        }
        return list;
    }
}
