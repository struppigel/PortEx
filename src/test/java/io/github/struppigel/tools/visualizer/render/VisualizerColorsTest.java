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
package io.github.struppigel.tools.visualizer.render;

import org.testng.annotations.Test;

import java.util.Random;

import static io.github.struppigel.tools.visualizer.render.VisualizerColors.*;
import static org.testng.Assert.*;

public class VisualizerColorsTest {

    @Test
    public void textColorByContrast() {
        // olive and yellow byte plot cells get black text
        assertEquals(textRgbFor(0x808000), BLACK_TEXT);
        assertEquals(textRgbFor(0xFFFF00), BLACK_TEXT);
        assertEquals(textRgbFor(0xFFFFFF), BLACK_TEXT);
        // dark cells get white text
        assertEquals(textRgbFor(0x000080), WHITE_TEXT);
        assertEquals(textRgbFor(0x000000), WHITE_TEXT);
        // alpha is ignored
        assertEquals(textRgbFor(0xFF808000), BLACK_TEXT);
    }

    @Test
    public void chosenTextColorHasEnoughContrast() {
        Random random = new Random(1);
        for (int i = 0; i < 100_000; i++) {
            int background = random.nextInt() & 0xFFFFFF;
            int text = textRgbFor(background);
            double chosen = contrastRatio(text, background);
            double other = contrastRatio(text == BLACK_TEXT ? WHITE_TEXT : BLACK_TEXT, background);
            assertTrue(chosen >= 4.5, Integer.toHexString(background) + " contrast " + chosen);
            assertTrue(chosen >= other - 0.05, Integer.toHexString(background));
        }
    }

    @Test
    public void wcagValues() {
        assertEquals(relativeLuminance(0x000000), 0.0, 1e-9);
        assertEquals(relativeLuminance(0xFFFFFF), 1.0, 1e-9);
        assertEquals(contrastRatio(0x000000, 0xFFFFFF), 21.0, 1e-9);
        assertEquals(contrastRatio(0x808000, 0x000000), 5.0, 0.05);
        assertEquals(contrastRatio(0x808000, 0xFFFFFF), 4.2, 0.05);
    }
}
