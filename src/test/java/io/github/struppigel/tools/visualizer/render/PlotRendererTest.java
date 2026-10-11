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

import io.github.struppigel.tools.ShannonEntropy;
import io.github.struppigel.tools.layout.StructureMap;
import io.github.struppigel.tools.visualizer.engine.ByteClass;
import io.github.struppigel.tools.visualizer.engine.ByteStatistics;
import io.github.struppigel.tools.visualizer.engine.ByteStats;
import io.github.struppigel.tools.visualizer.engine.CachedByteSource;
import io.github.struppigel.tools.visualizer.engine.FileVisualization;
import io.github.struppigel.tools.visualizer.engine.ProgressListener;
import io.github.struppigel.tools.visualizer.engine.ViewMapping;
import io.github.struppigel.tools.visualizer.engine.Viewport;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Random;

import static io.github.struppigel.tools.visualizer.render.RenderTestSupport.*;
import static org.testng.Assert.*;

/** tests of the byte plot, entropy and hex renderers on generated files */
public class PlotRendererTest {

    private File file;
    private byte[] content;

    @BeforeClass
    public void createFile() throws IOException {
        // 64 KB zeros, 64 KB random, 64 KB text
        content = new byte[3 << 16];
        byte[] random = new byte[1 << 16];
        new Random(5).nextBytes(random);
        System.arraycopy(random, 0, content, 1 << 16, random.length);
        for (int i = 2 << 16; i < content.length; i++) {
            content[i] = (byte) ('a' + i % 26);
        }
        file = File.createTempFile("portex-plot", ".bin");
        file.deleteOnExit();
        Files.write(file.toPath(), content);
    }

    @AfterClass
    public void deleteFile() {
        file.delete();
    }

    private FileVisualization vis(boolean computed) throws IOException {
        StructureMap map = StructureMap.empty(content.length);
        ByteStatistics stats = new ByteStatistics(file);
        if (computed) {
            stats.compute(ProgressListener.NONE);
        }
        return new FileVisualization(map, stats, new CachedByteSource(file), RegionColorScheme.of(map));
    }

    @Test
    public void dominantClassColors() throws IOException {
        FileVisualization vis = vis(true);
        RegionColorScheme scheme = vis.getColorScheme();
        for (long bpc : new long[]{16, 256, 1024}) {
            ViewMapping mapping = new ViewMapping(content.length, 0, bpc, 16);
            Viewport viewport = new Viewport(mapping, 0, (int) mapping.getRowCount(), 2);
            int[] argb = render(Track.BYTEPLOT, vis, viewport, 2, RenderStyle.defaults());
            assertEquals(pixelAt(argb, viewport, 2, 100), scheme.bytePlotRgb(0), "zeros at bpc " + bpc);
            long textCell = (2 << 16) + 7 * bpc;
            double mean;
            if (bpc >= vis.getStatistics().getBlockSize()) {
                ByteStats stats = new ByteStats();
                vis.getStatistics().aggregate(textCell, textCell + bpc, stats);
                mean = stats.getMeanValue(ByteClass.PRINTABLE);
            } else {
                // cells smaller than a block are computed from their bytes
                long sum = 0;
                for (long i = textCell; i < textCell + bpc; i++) sum += content[(int) i];
                mean = sum / (double) bpc;
            }
            assertEquals(pixelAt(argb, viewport, 2, textCell), scheme.classRgb(ByteClass.PRINTABLE, mean),
                    "text at bpc " + bpc);
        }
    }

    @Test
    public void firstByteSamplesBytes() throws IOException {
        FileVisualization vis = vis(false);
        ViewMapping mapping = new ViewMapping(content.length, 0, 100, 8);
        Viewport viewport = new Viewport(mapping, 0, (int) mapping.getRowCount(), 1);
        RenderStyle style = RenderStyle.legacy();
        int[] argb = render(Track.BYTEPLOT, vis, viewport, 1, style);
        for (long cell = 0; cell * 100 < content.length; cell += 37) {
            assertEquals(argb[(int) cell], vis.getColorScheme().bytePlotRgb(content[(int) (cell * 100)]));
        }
        // with a sample step the cell shows the last sample before its end, like the classic visualizer
        argb = render(Track.BYTEPLOT, vis, viewport, 1, style.withSampleStep(30));
        assertEquals(argb[0], vis.getColorScheme().bytePlotRgb(content[90]));
        assertEquals(argb[1], vis.getColorScheme().bytePlotRgb(content[180]));
    }

    @Test
    public void meanEntropyFromStatisticsAndBytes() throws IOException {
        FileVisualization vis = vis(true);
        RegionColorScheme scheme = vis.getColorScheme();
        // large cells use the statistics
        ViewMapping coarse = new ViewMapping(content.length, 0, 4096, 4);
        Viewport viewport = new Viewport(coarse, 0, (int) coarse.getRowCount(), 2);
        int[] argb = render(Track.ENTROPY, vis, viewport, 2, RenderStyle.defaults());
        ByteStats stats = new ByteStats();
        vis.getStatistics().aggregate(1 << 16, (1 << 16) + 4096, stats);
        assertEquals(pixelAt(argb, viewport, 2, 1 << 16), scheme.entropyRgb(stats.getMeanEntropy()));
        assertEquals(pixelAt(argb, viewport, 2, 0), scheme.entropyRgb(0));
        // small cells are computed from the bytes
        ViewMapping fine = new ViewMapping(content.length, 0, 1, 64);
        Viewport fineView = new Viewport(fine, fine.rowOf(1 << 16) + 10, 4, 2);
        int[] fineArgb = render(Track.ENTROPY, vis, fineView, 2, RenderStyle.defaults());
        long offset = fine.cellStart(fineView.getFirstRow(), 5);
        double expected = ShannonEntropy.entropy(Arrays.copyOfRange(content, (int) offset - 128, (int) offset + 128));
        assertEquals(pixelAt(fineArgb, fineView, 2, offset), scheme.entropyRgb(expected));
    }

    @Test
    public void legacyWindowEntropy() throws IOException {
        FileVisualization vis = vis(false);
        ViewMapping mapping = new ViewMapping(content.length, 0, 1000, 8);
        Viewport viewport = new Viewport(mapping, 0, (int) mapping.getRowCount(), 1);
        int[] argb = render(Track.ENTROPY, vis, viewport, 1, RenderStyle.legacy());
        // cell 70 starts at 70000 in the random part, the window is 50 bytes on each side
        double expected = ShannonEntropy.entropy(Arrays.copyOfRange(content, 70000 - 50, 70000 + 50));
        assertEquals(argb[70], vis.getColorScheme().entropyRgb(expected));
        expected = ShannonEntropy.entropy(Arrays.copyOfRange(content, 0, 100));
        assertEquals(argb[0], vis.getColorScheme().entropyRgb(expected));
    }

    @Test
    public void pendingStatisticsAreHatched() throws IOException {
        FileVisualization vis = vis(false);
        ViewMapping mapping = new ViewMapping(content.length, 0, 1024, 8);
        Viewport viewport = new Viewport(mapping, 0, (int) mapping.getRowCount(), 8);
        RenderStyle style = RenderStyle.defaults();
        for (Track track : new Track[]{Track.BYTEPLOT, Track.ENTROPY}) {
            int[] argb = render(track, vis, viewport, 8, style);
            boolean hatch = false;
            boolean background = false;
            for (int pixel : argb) {
                hatch |= pixel == style.getHatchColor();
                background |= pixel == style.getBackground();
            }
            assertTrue(hatch && background, track + " is not hatched");
        }
        vis.getStatistics().compute(ProgressListener.NONE);
        int[] argb = render(Track.ENTROPY, vis, viewport, 8, style);
        for (int pixel : argb) {
            assertNotEquals(pixel, style.getHatchColor());
        }
    }

    @Test
    public void hexShowsBytesOnStructureColors() throws IOException {
        FileVisualization vis = visualization("HelloWorld.exe", false);
        ViewMapping mapping = new ViewMapping(vis.getFileLength(), 0x80, 1, 16);
        Viewport viewport = new Viewport(mapping, 0, 2, 14);
        int[] hex = render(Track.HEX, vis, viewport, 20, RenderStyle.defaults());
        int[] ascii = render(Track.ASCII, vis, viewport, 10, RenderStyle.defaults());
        // the glyphs differ: 'P' (0x50) and 'E' (0x45) of the PE signature
        int[] p = cell(hex, 20, 14, 16, 0, 0);
        int[] e = cell(hex, 20, 14, 16, 0, 1);
        assertFalse(Arrays.equals(p, e));
        assertFalse(Arrays.equals(cell(ascii, 10, 14, 16, 0, 0), cell(ascii, 10, 14, 16, 0, 1)));
        // the same byte value looks the same: 00 00 after "PE"
        assertEquals(cell(hex, 20, 14, 16, 0, 2), cell(hex, 20, 14, 16, 0, 3));
    }

    private static int[] cell(int[] argb, int cellWidth, int cellHeight, int columns, int row, int column) {
        int[] result = new int[cellWidth * cellHeight];
        int width = columns * cellWidth;
        for (int y = 0; y < cellHeight; y++) {
            System.arraycopy(argb, (row * cellHeight + y) * width + column * cellWidth, result, y * cellWidth,
                    cellWidth);
        }
        return result;
    }

    @Test
    public void compositeHasAllParts() throws IOException {
        FileVisualization vis = visualization("WinRar.exe", true);
        ViewMapping mapping = new ViewMapping(vis.getFileLength(), 0x200, 1, 16);
        BufferedImage image = VisualizationRenderer.renderComposite(vis, mapping, 0, 20,
                Arrays.asList(Track.BYTEPLOT, Track.ENTROPY, Track.STRUCTURE, Track.HEX), 4, 14,
                RenderStyle.defaults(), true);
        // the legend is as wide as its labels need, at least LEGEND_WIDTH
        int legendWidth = LegendRenderer.fittedWidth(LegendRenderer.entries(vis.getStructureMap(),
                vis.getColorScheme(), true, true, RenderStyle.defaults().getPaintedTypes()), 20 * 14);
        assertTrue(legendWidth > VisualizationRenderer.LEGEND_WIDTH, "legend width " + legendWidth);
        int expectedWidth = VisualizationRenderer.RULER_WIDTH + 4 * VisualizationRenderer.TRACK_GAP
                + 16 * (4 + 4 + 4 + VisualizationRenderer.HEX_CELL_WIDTH)
                + VisualizationRenderer.TRACK_GAP + legendWidth;
        assertEquals(image.getWidth(), expectedWidth);
        assertEquals(image.getHeight(), 20 * 14);
    }
}
