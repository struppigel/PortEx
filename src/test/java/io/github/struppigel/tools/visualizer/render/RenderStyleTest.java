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

import io.github.struppigel.tools.layout.RegionType;
import org.testng.annotations.Test;

import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.*;

public class RenderStyleTest {

    @Test
    public void presetsUseStructureAsHexBackground() {
        assertEquals(RenderStyle.defaults().getHexBackground(), Track.STRUCTURE);
        assertEquals(RenderStyle.legacy().getHexBackground(), Track.STRUCTURE);
    }

    @Test
    public void hexBackgroundRoundTrip() {
        for (Track track : new Track[]{Track.STRUCTURE, Track.BYTEPLOT, Track.ENTROPY}) {
            RenderStyle style = RenderStyle.defaults().withHexBackground(track);
            assertEquals(style.getHexBackground(), track);
            // other settings are kept
            assertEquals(style.withHexBackground(Track.STRUCTURE), RenderStyle.defaults());
        }
        RenderStyle changed = RenderStyle.defaults().withHexBackground(Track.ENTROPY).withAdditionalGap(3);
        assertEquals(changed.getHexBackground(), Track.ENTROPY);
    }

    @Test
    public void equalityIncludesHexBackground() {
        RenderStyle structure = RenderStyle.defaults();
        RenderStyle bytePlot = RenderStyle.defaults().withHexBackground(Track.BYTEPLOT);
        assertNotEquals(bytePlot, structure);
        assertNotEquals(bytePlot.hashCode(), structure.hashCode());
        assertEquals(bytePlot, RenderStyle.defaults().withHexBackground(Track.BYTEPLOT));
        assertEquals(bytePlot.hashCode(), RenderStyle.defaults().withHexBackground(Track.BYTEPLOT).hashCode());
        assertTrue(bytePlot.toString().contains("BYTEPLOT"));
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void hexIsNoHexBackground() {
        RenderStyle.defaults().withHexBackground(Track.HEX);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void asciiIsNoHexBackground() {
        RenderStyle.defaults().withHexBackground(Track.ASCII);
    }

    @Test(expectedExceptions = NullPointerException.class)
    public void nullIsNoHexBackground() {
        RenderStyle.defaults().withHexBackground(null);
    }

    @Test
    public void defaultHexFontIsInstalled() {
        String family = RenderStyle.defaults().getHexFontFamily();
        assertEquals(family, RenderStyle.defaultHexFontFamily());
        assertEquals(RenderStyle.legacy().getHexFontFamily(), family);
        List<String> installed = Arrays.asList(
                GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames());
        assertTrue(installed.contains(family) || family.equals(Font.MONOSPACED), family);
    }

    @Test
    public void hexFontFamilyRoundTrip() {
        assertEquals(RenderStyle.defaults().withHexFontFamily(Font.SANS_SERIF).getHexFontFamily(), Font.SANS_SERIF);
        assertEquals(RenderStyle.defaults().withHexFontFamily(Font.MONOSPACED).getHexFontFamily(), Font.MONOSPACED);
        // the installed spelling is used
        assertEquals(RenderStyle.defaults().withHexFontFamily(" sansserif ").getHexFontFamily(), Font.SANS_SERIF);
        RenderStyle changed = RenderStyle.defaults().withHexFontFamily(Font.SANS_SERIF).withAdditionalGap(2);
        assertEquals(changed.getHexFontFamily(), Font.SANS_SERIF);
    }

    @Test
    public void missingHexFontFamilyGivesTheDefault() {
        String fallback = RenderStyle.defaultHexFontFamily();
        assertEquals(RenderStyle.defaults().withHexFontFamily(null).getHexFontFamily(), fallback);
        assertEquals(RenderStyle.defaults().withHexFontFamily("").getHexFontFamily(), fallback);
        assertEquals(RenderStyle.defaults().withHexFontFamily("   ").getHexFontFamily(), fallback);
        assertEquals(RenderStyle.defaults().withHexFontFamily("No Such Font 123").getHexFontFamily(), fallback);
        assertEquals(RenderStyle.defaults().withHexFontFamily("No Such Font 123"), RenderStyle.defaults());
    }

    @Test
    public void equalityIncludesHexFontFamily() {
        RenderStyle mono = RenderStyle.defaults().withHexFontFamily(Font.MONOSPACED);
        RenderStyle sans = RenderStyle.defaults().withHexFontFamily(Font.SANS_SERIF);
        assertNotEquals(mono, sans);
        assertNotEquals(mono.hashCode(), sans.hashCode());
        assertEquals(sans, RenderStyle.defaults().withHexFontFamily("SansSerif"));
        assertEquals(sans.hashCode(), RenderStyle.defaults().withHexFontFamily("SansSerif").hashCode());
        assertTrue(sans.toString().contains("SansSerif"));
    }

    @Test
    public void hexText() {
        assertTrue(RenderStyle.defaults().isHexText());
        assertTrue(RenderStyle.legacy().isHexText());
        RenderStyle plain = RenderStyle.defaults().withHexText(false);
        assertFalse(plain.isHexText());
        assertTrue(plain.withHexText(true).isHexText());
        assertEquals(plain.withHexText(true), RenderStyle.defaults());
        assertNotEquals(plain, RenderStyle.defaults());
        assertNotEquals(plain.hashCode(), RenderStyle.defaults().hashCode());
        assertTrue(plain.toString().contains("hex text=false"));
        // other settings keep the text setting
        assertFalse(plain.withHexBackground(Track.ENTROPY).withHexFontFamily(Font.SANS_SERIF).isHexText());
    }

    @Test
    public void markerToggle() {
        RenderStyle style = RenderStyle.defaults().withPainted(RegionType.ANOMALY, false);
        assertFalse(style.paints(RegionType.ANOMALY));
        assertTrue(style.withPainted(RegionType.ANOMALY, true).paints(RegionType.ANOMALY));
        assertEquals(style.withPainted(RegionType.ANOMALY, true), RenderStyle.defaults());
    }
}
