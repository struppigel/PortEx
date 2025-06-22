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
package io.github.struppigel.tools.sigscanner;

import io.github.struppigel.tools.sigscanner.v2.Pattern;
import io.github.struppigel.tools.sigscanner.v2.PatternParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class PatternTest {

    @SuppressWarnings("unused")
    private static final Logger logger = LogManager
            .getLogger(PatternTest.class.getName());

    @Test
    public void testBoundlessRange() {
        byte[] bytes = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        String input = "01 02 03 04 05 [3-] 08 09 0A";
        Pattern pattern = PatternParser.parseInit(input);
        assertFalse(pattern.matches(bytes));
        input = "01 02 03 04 05 [2-] 08 09 0A";
        pattern = PatternParser.parseInit(input);
        assertTrue(pattern.matches(bytes));
    }

    @Test
    public void testLimitedRange() {
        byte[] bytes = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        String input = "01 02 03 04 05 [-2] 09 0A";
        Pattern pattern = PatternParser.parseInit(input);
        assertFalse(pattern.matches(bytes));
        input = "01 02 03 04 05 [-3] 09 0A";
        pattern = PatternParser.parseInit(input);
        assertTrue(pattern.matches(bytes));

        input = "01 02 03 04 05 [2-3] 09 0A";
        pattern = PatternParser.parseInit(input);
        assertTrue(pattern.matches(bytes));
    }

    @Test
    public void testWildcards() {
        byte[] bytes = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        String input = "01 ?2 ?? 04 0? 06";
        Pattern pattern = PatternParser.parseInit(input);
        assertTrue(pattern.matches(bytes));
        input = "01 ?2 ?? 04 ?? 0? 06";
        pattern = PatternParser.parseInit(input);
        assertFalse(pattern.matches(bytes));
    }

    @Test
    public void testPatternParser() {
        String input = "CA F? (CA|?F BA | CA ?? 11 [1-2]BE )ba?? b???BABE ?B (AB | BB |BC | CD | EF)";
        String parseResult = "CA F? (CA|(?F BA|CA ?? 11 [1-2] BE)) BA ?? B? ?? BA BE ?B (AB|(BB|(BC|(CD|EF))))";
        Pattern pattern = PatternParser.parseInit(input);
        assertEquals(pattern.toString(), parseResult);

    }

    @Test
    public void testPOption() {
        byte[] bytes = {1,2,3,4};
        String input = "01 02 (?? 04 | 04)";
        Pattern pattern = PatternParser.parseInit(input);
        assertTrue(pattern.matches(bytes));
        input = "01 02 ( 04 | 03 | 02 01 ) 04";
        pattern = PatternParser.parseInit(input);
        assertTrue(pattern.matches(bytes));
    }

}
