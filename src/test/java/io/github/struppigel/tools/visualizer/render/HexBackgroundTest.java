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

import io.github.struppigel.tools.visualizer.engine.FileVisualization;
import io.github.struppigel.tools.visualizer.engine.ViewMapping;
import io.github.struppigel.tools.visualizer.engine.Viewport;
import org.testng.annotations.Test;

import java.awt.Font;
import java.io.IOException;

import static io.github.struppigel.tools.visualizer.render.RenderTestSupport.*;
import static org.testng.Assert.*;

/** the cell backgrounds of the hex and ASCII tracks */
public class HexBackgroundTest {

    private static final int CELL_HEIGHT = 14;

    /** the PE signature of HelloWorld.exe is at 0x80: 50 45 00 00 */
    private static Viewport peSignatureRows(FileVisualization vis) {
        return new Viewport(new ViewMapping(vis.getFileLength(), 0x80, 1, 16), 0, 4, CELL_HEIGHT);
    }

    /** the top left pixel of a cell, which the glyph does not cover */
    private static int corner(int[] argb, int cellWidth, int row, int column) {
        return argb[row * CELL_HEIGHT * 16 * cellWidth + column * cellWidth];
    }

    @Test
    public void bytePlotBackground() throws IOException {
        FileVisualization vis = visualization("HelloWorld.exe", false);
        Viewport viewport = peSignatureRows(vis);
        RenderStyle style = RenderStyle.defaults().withHexBackground(Track.BYTEPLOT);
        RegionColorScheme scheme = vis.getColorScheme();
        for (Track track : new Track[]{Track.HEX, Track.ASCII}) {
            int cellWidth = track == Track.HEX ? 20 : 10;
            int[] argb = render(track, vis, viewport, cellWidth, style);
            assertEquals(corner(argb, cellWidth, 0, 0), scheme.bytePlotRgb('P'), track + " P");
            assertEquals(corner(argb, cellWidth, 0, 1), scheme.bytePlotRgb('E'), track + " E");
            assertEquals(corner(argb, cellWidth, 0, 2), scheme.bytePlotRgb(0), track + " zero");
            // the background equals the byte plot track at every byte
            int[] plot = render(Track.BYTEPLOT, vis, viewport, cellWidth, style);
            for (int row = 0; row < 4; row++) {
                for (int column = 0; column < 16; column++) {
                    assertEquals(corner(argb, cellWidth, row, column),
                            plot[(row * CELL_HEIGHT + CELL_HEIGHT / 2) * 16 * cellWidth + column * cellWidth
                                    + cellWidth / 2], track + " cell " + row + "/" + column);
                }
            }
        }
    }

    @Test
    public void entropyBackground() throws IOException {
        FileVisualization vis = visualization("HelloWorld.exe", false);
        Viewport viewport = peSignatureRows(vis);
        RenderStyle style = RenderStyle.defaults().withHexBackground(Track.ENTROPY);
        int[] hex = render(Track.HEX, vis, viewport, 20, style);
        int[] entropy = render(Track.ENTROPY, vis, viewport, 20, style);
        for (int row = 0; row < 4; row++) {
            for (int column = 0; column < 16; column++) {
                int centre = entropy[(row * CELL_HEIGHT + CELL_HEIGHT / 2) * 16 * 20 + column * 20 + 10];
                assertEquals(corner(hex, 20, row, column), centre, "cell " + row + "/" + column);
            }
        }
    }

    @Test
    public void fontFamilyChangesTheGlyphs() throws IOException {
        FileVisualization vis = visualization("HelloWorld.exe", false);
        Viewport viewport = peSignatureRows(vis);
        RenderStyle mono = RenderStyle.defaults().withHexFontFamily(Font.MONOSPACED);
        RenderStyle sans = RenderStyle.defaults().withHexFontFamily(Font.SANS_SERIF);
        for (Track track : new Track[]{Track.HEX, Track.ASCII}) {
            int cellWidth = track == Track.HEX ? 20 : 10;
            int[] monoPixels = render(track, vis, viewport, cellWidth, mono);
            int[] sansPixels = render(track, vis, viewport, cellWidth, sans);
            // the cells of the same bytes look different in another family
            assertNotEquals(sansPixels, monoPixels, track.toString());
            // the glyphs of one family are not reused for the other
            assertEquals(render(track, vis, viewport, cellWidth, mono), monoPixels, track.toString());
            assertEquals(render(track, vis, viewport, cellWidth, sans), sansPixels, track.toString());
        }
    }

    @Test
    public void cellsWithoutText() throws IOException {
        FileVisualization vis = visualization("HelloWorld.exe", false);
        Viewport viewport = peSignatureRows(vis);
        for (Track background : new Track[]{Track.STRUCTURE, Track.BYTEPLOT, Track.ENTROPY}) {
            for (Track track : new Track[]{Track.HEX, Track.ASCII}) {
                int cellWidth = track == Track.HEX ? 20 : 10;
                int width = 16 * cellWidth;
                RenderStyle style = RenderStyle.defaults().withHexBackground(background);
                int[] text = render(track, vis, viewport, cellWidth, style);
                int[] plain = render(track, vis, viewport, cellWidth, style.withHexText(false));
                boolean glyphs = false;
                for (int row = 0; row < 4; row++) {
                    for (int column = 0; column < 16; column++) {
                        int corner = corner(plain, cellWidth, row, column);
                        for (int py = 0; py < CELL_HEIGHT; py++) {
                            for (int px = 0; px < cellWidth; px++) {
                                int i = (row * CELL_HEIGHT + py) * width + column * cellWidth + px;
                                boolean grid = px == cellWidth - 1 || py == CELL_HEIGHT - 1;
                                if (grid) {
                                    // the grid is the same with and without text
                                    assertEquals(plain[i], text[i], background + " " + track);
                                } else {
                                    // no glyph pixels, every cell is uniform
                                    assertEquals(plain[i], corner, background + " " + track);
                                    // the text tile only differs where glyphs are drawn
                                    glyphs |= text[i] != plain[i];
                                }
                            }
                        }
                        assertEquals(corner(text, cellWidth, row, column), corner);
                    }
                }
                assertTrue(glyphs, "no glyphs with text for " + background + " " + track);
            }
        }
    }

    @Test
    public void structureIsTheDefaultBackground() throws IOException {
        FileVisualization vis = visualization("HelloWorld.exe", false);
        Viewport viewport = peSignatureRows(vis);
        int[] defaults = render(Track.HEX, vis, viewport, 20, RenderStyle.defaults());
        int[] structure = render(Track.HEX, vis, viewport, 20,
                RenderStyle.defaults().withHexBackground(Track.STRUCTURE));
        assertEquals(structure, defaults);
        int[] bytePlot = render(Track.HEX, vis, viewport, 20,
                RenderStyle.defaults().withHexBackground(Track.BYTEPLOT));
        assertNotEquals(bytePlot, defaults);
    }
}
