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
package com.github.katjahahn.msdos;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.TestreportsReader;
import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoader;
import com.github.katjahahn.parser.msdos.MSDOSHeader;
import com.github.katjahahn.parser.msdos.MSDOSLoadModule;

public class MSDOSLoadModuleTest {

    private MSDOSLoadModule module;
    private File file;

    @BeforeClass
    public void prepare() throws IOException {
        file = new File(TestreportsReader.RESOURCE_DIR + "/WinRar.exe");
        PEData data = PELoader.loadPE(file);
        MSDOSHeader header = data.getMSDOSHeader();
        module = new MSDOSLoadModule(header, file);
        module.read();
    }

    @Test
    public void getDump() throws IOException {
        byte[] bytes = module.getDump();
        assertNotNull(bytes);
        assertTrue(bytes.length > 0);
    }

    @Test
    public void getLoadModuleSize() {
        int size = module.getLoadModuleSize();
        assertTrue(size > 0 && size < file.length());
    }

    @Test
    public void getImageSize() {
        int size = module.getImageSize();
        assertTrue(size > 0 && size < file.length());
    }

    @Test
    public void getInfo() {
        String info = module.getInfo();
        assertNotNull(info);
        assertTrue(info.length() > 0);
    }
}
