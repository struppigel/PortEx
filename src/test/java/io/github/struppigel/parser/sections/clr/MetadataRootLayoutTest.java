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
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.PhysicalLocation;
import io.github.struppigel.parser.sections.SectionLoader;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;

import static org.testng.Assert.assertEquals;

public class MetadataRootLayoutTest {

    private static final String DIR = TestreportsReader.RESOURCE_DIR + "/testfiles/";

    @Test
    public void stream_header_size_includes_the_terminator_and_padding() {
        // name + zero terminator, padded to a multiple of 4
        assertEquals(new StreamHeader(0, 0, "#~").getHeaderSize(), 8 + 4);
        assertEquals(new StreamHeader(0, 0, "#GUID").getHeaderSize(), 8 + 8);
        assertEquals(new StreamHeader(0, 0, "#Blob").getHeaderSize(), 8 + 8);
        assertEquals(new StreamHeader(0, 0, "#US").getHeaderSize(), 8 + 4);
        assertEquals(new StreamHeader(0, 0, "#Strings").getHeaderSize(), 8 + 12);
        assertEquals(new StreamHeader(0, 0, "#abc").getHeaderSize(), 8 + 8);
    }

    @Test
    public void metadata_root_location_ends_where_the_first_stream_starts() throws IOException {
        for (String name : new String[]{"HelloWorld.exe", "NetCoreConsole.dll"}) {
            MetadataRoot root = new SectionLoader(PELoader.loadPE(new File(DIR + name))).loadCLRSection()
                    .getMetadataRoot();
            long firstStream = root.getStreamHeaders().stream().mapToLong(StreamHeader::offset).min().getAsLong();
            PhysicalLocation location = root.getPhysicalLocations().head();
            assertEquals(location.size(), firstStream, name);
        }
    }
}
