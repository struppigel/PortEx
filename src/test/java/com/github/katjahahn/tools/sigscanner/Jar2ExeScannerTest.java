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
package com.github.katjahahn.tools.sigscanner;

import static org.testng.Assert.*;

import java.io.File;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.Test;

import com.github.katjahahn.TestreportsReader;
import com.github.katjahahn.tools.sigscanner.Jar2ExeScanner;
import com.github.katjahahn.tools.sigscanner.MatchedSignature;

public class Jar2ExeScannerTest {

    @SuppressWarnings("unused")
    private static final Logger logger = LogManager
            .getLogger(Jar2ExeScannerTest.class.getName());

    @Test
    // TODO
    public void scanResultTest() {
        Jar2ExeScanner scanner = new Jar2ExeScanner(new File(
                TestreportsReader.RESOURCE_DIR + "/launch4jexe.exe"));
        List<MatchedSignature> result = scanner.scan();
        assertTrue(contains(result, "[Launch4j]"));
    }

    private boolean contains(List<MatchedSignature> siglist, String name) {
        for (MatchedSignature sig : siglist) {
            if (sig.name.equals(name))
                return true;
        }
        return false;
    }
}
