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
package com.github.katjahahn.tools;

import com.github.katjahahn.TestreportsReader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;

import static org.testng.Assert.*;

public class OverlayTest {
    // TODO test the testfiles
    @SuppressWarnings("unused")
    private static final Logger logger = LogManager.getLogger(OverlayTest.class
            .getName());

    @Test(timeOut = 9000)
    public void hasOverlayTest() throws IOException {
        String[] files = { TestreportsReader.RESOURCE_DIR
                + "/testfiles/Lab03-04",
                TestreportsReader.RESOURCE_DIR + "/testfiles/adodb.dll"
        };
        for (String file : files) {
            File infile = new File(file);
            Overlay overlay = new Overlay(infile);
            assertFalse(overlay.exists());
        }
        String[] overfiles = {
                TestreportsReader.RESOURCE_DIR + "/testfiles/WinRar.exe",
                TestreportsReader.RESOURCE_DIR + "/testfiles/WMIX.exe" };
        for (String file : overfiles) {
            File infile = new File(file);
            Overlay overlay = new Overlay(infile);
            assertTrue(overlay.exists());
        }
    }

    @Test(timeOut = 9000)
    public void eofNoOverlayTest() throws IOException {
        String[] noOverFiles = { TestreportsReader.RESOURCE_DIR
                + "/testfiles/Lab03-04",
                TestreportsReader.RESOURCE_DIR + "/testfiles/adodb.dll"
        };
        for (String file : noOverFiles) {
            File infile = new File(file);
            Overlay overlay = new Overlay(infile);
            long eof = overlay.getOffset();
            assertEquals(infile.length(), eof);
        }
    }

    @Test
    public void dumpTo() throws IOException {
        String[] mixedFiles = {
                TestreportsReader.RESOURCE_DIR + "/testfiles/Lab03-01",
                TestreportsReader.RESOURCE_DIR + "/testfiles/Lab03-04",
                TestreportsReader.RESOURCE_DIR + "/testfiles/Lab03-03",
                TestreportsReader.RESOURCE_DIR + "/testfiles/WinRar.exe"
        };
        File outfile = new File("out");
        for (String file : mixedFiles) {
            File infile = new File(file);
            Overlay overlay = new Overlay(infile);
            overlay.dumpTo(outfile);
        }
        outfile.delete();
    }

}
