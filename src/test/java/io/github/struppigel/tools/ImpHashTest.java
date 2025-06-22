/**
 * *****************************************************************************
 * Copyright 2021 Karsten Philipp Boris Hahn
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
package io.github.struppigel.tools;

import io.github.struppigel.TestreportsReader;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static org.testng.Assert.assertEquals;

public class ImpHashTest {

    private File stringsfile;

    private File ordfile;

    private File mixedfile;

    @BeforeClass
    public void prepare() throws IOException, NoSuchAlgorithmException {
        this.stringsfile = new File(TestreportsReader.RESOURCE_DIR
                + TestreportsReader.TEST_FILE_DIR + "/strings.exe");
        this.ordfile = new File(TestreportsReader.RESOURCE_DIR
                + "/corkami/impbyord.exe");
        this.mixedfile = new File(TestreportsReader.RESOURCE_DIR + TestreportsReader.TEST_FILE_DIR + "/WMIX.exe");
    }

    @Test
    public void calculate() {
        assertEquals(ImpHash.createString(stringsfile), "cdc0bddd514e6d3c047926379e3c9a62");
        assertEquals(ImpHash.createString(ordfile), "806635f2551e40916dcfd4c38c761baa");
        assertEquals(ImpHash.createString(mixedfile), "cbc19a820310308f17b0a7c562d044e0");
    }
}
