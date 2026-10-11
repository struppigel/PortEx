/*******************************************************************************
 * Copyright 2014 Karsten Philipp Boris Hahn
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
import io.github.struppigel.parser.msdos.MSDOSHeaderKey;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotSame;
import static org.testng.Assert.assertTrue;

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

    @Test
    public void initFullEnumMapReturnsIndependentInitializedMaps() {
        Map<MSDOSHeaderKey, StandardField> first = IOUtil.initFullEnumMap(MSDOSHeaderKey.class);
        Map<MSDOSHeaderKey, StandardField> second = IOUtil.initFullEnumMap(MSDOSHeaderKey.class);

        assertNotSame(first, second);
        assertEquals(first.size(), MSDOSHeaderKey.values().length);
        assertEquals(second.size(), MSDOSHeaderKey.values().length);
        for (MSDOSHeaderKey key : MSDOSHeaderKey.values()) {
            assertEquals(first.get(key).getDescription(), "this field was not set");
            assertEquals(second.get(key).getDescription(), "this field was not set");
        }

        MSDOSHeaderKey key = MSDOSHeaderKey.values()[0];
        first.put(key, new StandardField(key, "changed", 1L, 2L, 3L));
        assertTrue(first.get(key).getDescription().equals("changed"));
        assertEquals(second.get(key).getDescription(), "this field was not set");
        assertEquals(IOUtil.initFullEnumMap(MSDOSHeaderKey.class).get(key).getDescription(),
                "this field was not set");
    }

    @Test
    public void readHeaderEntriesForSpecCanReturnOnlySpecifiedFields() {
        List<String[]> specification = new ArrayList<>();
        specification.add(new String[] {"SIGNATURE_WORD", "signature", "0", "2"});
        byte[] headerBytes = {(byte) 0x4d, (byte) 0x5a};
        IOUtil.SpecificationFormat format = new IOUtil.SpecificationFormat(0, 1, 2, 3);

        Map<MSDOSHeaderKey, StandardField> full = IOUtil.readHeaderEntriesForSpec(
                MSDOSHeaderKey.class, format, specification, headerBytes, 100L);
        Map<MSDOSHeaderKey, StandardField> sparse = IOUtil.readHeaderEntriesForSpec(
                MSDOSHeaderKey.class, format, specification, headerBytes, 100L, false);

        assertEquals(full.size(), MSDOSHeaderKey.values().length);
        assertEquals(sparse.size(), 1);
        assertEquals(sparse.get(MSDOSHeaderKey.SIGNATURE_WORD).getValue(), 0x5a4dL);
        assertEquals(sparse.get(MSDOSHeaderKey.SIGNATURE_WORD).getOffset(), 100L);
        assertTrue(full.containsKey(MSDOSHeaderKey.FILE_PAGES));
        assertTrue(!sparse.containsKey(MSDOSHeaderKey.FILE_PAGES));
    }
}
