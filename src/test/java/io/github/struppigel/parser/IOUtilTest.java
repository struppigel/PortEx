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
package io.github.struppigel.parser;

import org.testng.annotations.Test;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;

public class IOUtilTest {

    @Test
    public void readArray() throws IOException {
        List<String[]> spec = IOUtil.readArray("msdosheaderspec");
        assertEquals(spec.size(), 31);
        for (String[] array : spec) {
            assertEquals(array.length, 4);
        }
    }

    @Test
    public void readMap() throws IOException {
        Map<String, String[]> spec = IOUtil.readMap("msdosheaderspec");
        assertEquals(spec.size(), 31);
        for (String[] array : spec.values()) {
            assertEquals(array.length, 3);
        }
    }
}
