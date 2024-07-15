/**
 * *****************************************************************************
 * Copyright 2024 Karsten Philipp Boris Hahn
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
 * ****************************************************************************
 */

package com.github.struppigel.parser.sections.idata;

import com.github.struppigel.parser.PEData;
import com.github.struppigel.parser.PELoader;
import com.github.struppigel.parser.sections.SectionLoader;
import com.github.struppigel.parser.sections.SectionLoaderTest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.util.List;


import static org.testng.Assert.assertEquals;

public class BoundImportSectionTest {

    private static final Logger logger = LogManager
            .getLogger(SectionLoaderTest.class.getName());

    @Test
    public void readBoundImportsAsRVAs() throws IOException {
        // this file is according to specification
        File file = new File("portextestfiles/corkami/dllbound-ld.exe");
        PEData data = PELoader.loadPE(file);
        BoundImportSection section = new SectionLoader(data).loadBoundImportSection();
        List<BoundImportDescriptor> descriptors = section.getEntries();
        assertEquals(descriptors.size(), 1);
        BoundImportDescriptor bi = descriptors.get(0);
        assertEquals(bi.get(BoundImportDescriptorKey.NR_OF_MODULE_FORWARDER_REFS), 0);
        assertEquals(bi.get(BoundImportDescriptorKey.OFFSET_MODULE_NAME), 0x10);
        assertEquals(bi.get(BoundImportDescriptorKey.TIME_DATE_STAMP), 0x31415925);
        assertEquals(bi.getName(), "dllbound.dll");
        assertEquals(bi.getPhysicalLocation().from(), 0x280);
    }

    @Test
    public void readBoundImportsAsFileOffsets() throws IOException {
        // this is an older file where bound imports use raw offsets instead of RVAs
        File file = new File("portextestfiles/BinaryCorpus_v2_oldCorkami/yoda/VB_boundimport.EXE");
        PEData data = PELoader.loadPE(file);
        BoundImportSection section = new SectionLoader(data).loadBoundImportSection();
        List<BoundImportDescriptor> descriptors = section.getEntries();
        System.out.println(section.getInfo());
        assertEquals(descriptors.size(), 1);
        BoundImportDescriptor bi = descriptors.get(0);
        assertEquals(bi.get(BoundImportDescriptorKey.NR_OF_MODULE_FORWARDER_REFS), 0);
        assertEquals(bi.get(BoundImportDescriptorKey.OFFSET_MODULE_NAME), 0x10);
        assertEquals(bi.get(BoundImportDescriptorKey.TIME_DATE_STAMP), 0x355c5ec3);
        assertEquals(bi.getName(), "MSVBVM60.DLL");
        assertEquals(bi.getPhysicalLocation().from(), 0x218);
    }

}
