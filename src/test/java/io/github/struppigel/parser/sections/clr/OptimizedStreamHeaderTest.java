/*******************************************************************************
 * Copyright 2026 Karsten Philipp Boris Hahn
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
package io.github.struppigel.parser.sections.clr;

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.StandardField;
import io.github.struppigel.parser.sections.SectionLoader;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/** The header of the #~ stream has two reserved fields, the second one is a single byte at offset 7. */
public class OptimizedStreamHeaderTest {

    private static final String DIR = TestreportsReader.RESOURCE_DIR + "/testfiles/";

    private ClrMutator mutator;

    @BeforeClass
    public void prepare() throws IOException {
        mutator = new ClrMutator(new File(DIR + "HelloWorld.exe"));
    }

    @AfterClass(alwaysRun = true)
    public void cleanup() throws IOException {
        mutator.delete();
    }

    private static OptimizedStream stream(PEData data) throws IOException {
        return new SectionLoader(data).loadCLRSection().getMetadataRoot().maybeGetOptimizedStream().get();
    }

    private static StandardField field(OptimizedStream stream, OptimizedStreamKey key) {
        StandardField field = stream.entries().get(key).get();
        assertNotNull(field);
        return field;
    }

    @Test
    public void second_reserved_field_is_read_from_offset_7() throws IOException {
        for (String name : new String[]{"HelloWorld.exe", "NetCoreConsole.dll"}) {
            OptimizedStream stream = stream(PELoader.loadPE(new File(DIR + name)));
            StandardField reserved = field(stream, OptimizedStreamKey.RESERVED_ONE);
            assertEquals(reserved.getValue(), 1L, name);
            assertEquals(reserved.getOffset(), stream.getRawOffset() + 7, name);
            assertEquals(field(stream, OptimizedStreamKey.RESERVED).getValue(), 0L, name);
        }
    }

    @Test
    public void changed_second_reserved_field_is_reported() throws IOException {
        long offset = mutator.tablesStream() + 7;
        OptimizedStream stream = stream(mutator.mutate(b -> b[(int) offset] = 0x2A));
        assertEquals(field(stream, OptimizedStreamKey.RESERVED_ONE).getValue(), 0x2AL);
    }
}
