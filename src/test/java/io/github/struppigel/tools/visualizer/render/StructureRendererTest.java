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

import io.github.struppigel.tools.layout.FileRegion;
import io.github.struppigel.tools.layout.PaintMode;
import io.github.struppigel.tools.layout.RegionType;
import io.github.struppigel.tools.layout.StructureMap;
import io.github.struppigel.tools.layout.StructureMapBuilder;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.tools.anomalies.PEAnomalyScanner;
import io.github.struppigel.tools.visualizer.engine.ByteStatistics;
import io.github.struppigel.tools.visualizer.engine.CachedByteSource;
import io.github.struppigel.tools.visualizer.engine.FileVisualization;
import io.github.struppigel.tools.visualizer.engine.ViewMapping;
import io.github.struppigel.tools.visualizer.engine.Viewport;
import org.testng.annotations.Test;

import java.io.File;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static io.github.struppigel.tools.visualizer.render.RenderTestSupport.*;
import static org.testng.Assert.*;

public class StructureRendererTest {

    @Test
    public void peSignatureHasItsColorAtEveryZoom() throws Exception {
        for (String name : new String[]{"WinRar.exe", "HelloWorld.exe"}) {
            FileVisualization vis = visualization(name, false);
            StructureMap map = vis.getStructureMap();
            FileRegion peSig = map.getRegions(RegionType.PE_SIGNATURE).get(0);
            int expected = vis.getColorScheme().rgbOf(peSig);
            // larger cells also contain the entry point, which is more specific
            for (long bytesPerCell : new long[]{1, 2, 4, 16, 64, 256}) {
                ViewMapping mapping = new ViewMapping(vis.getFileLength(), 0, bytesPerCell, 64);
                Viewport viewport = new Viewport(mapping, mapping.rowOf(peSig.getStart()), 4, 6);
                int[] argb = render(Track.STRUCTURE, vis, viewport, 6, RenderStyle.defaults());
                assertEquals(pixelAt(argb, viewport, 6, peSig.getStart()), expected,
                        name + " bytes per cell " + bytesPerCell);
            }
        }
    }

    @Test
    public void innermostRegionWinsAtTheMidpoint() throws Exception {
        FileVisualization vis = visualization("WinRar.exe", false);
        StructureMap map = vis.getStructureMap();
        ViewMapping mapping = new ViewMapping(vis.getFileLength(), 0, 1, 64);
        Viewport viewport = new Viewport(mapping, 0, (int) Math.min(mapping.getRowCount(), 2000), 2);
        int[] argb = render(Track.STRUCTURE, vis, viewport, 2, RenderStyle.defaults().withAdditionalGap(0));
        RenderStyle style = RenderStyle.defaults();
        for (long offset = 0; offset < viewport.getEndOffset(); offset += 7) {
            // the most specific filled region, unless an inset region or marker is on top
            int expected = style.getBackground();
            List<FileRegion> regions = map.regionsAt(offset);
            for (PaintMode pass : new PaintMode[]{PaintMode.MARKER, PaintMode.INSET, PaintMode.FILL}) {
                FileRegion top = null;
                for (FileRegion region : regions) {
                    if (region.getType().getPaintMode() == pass) {
                        top = region;
                        break;
                    }
                }
                if (top != null) {
                    expected = vis.getColorScheme().rgbOf(top);
                    break;
                }
            }
            assertEquals(Integer.toHexString(pixelAt(argb, viewport, 2, offset)), Integer.toHexString(expected),
                    "offset 0x" + Long.toHexString(offset) + " " + regions);
        }
    }

    @Test
    public void markersGetAtLeastOneCell() throws Exception {
        FileVisualization vis = visualization("WinRar.exe", false);
        FileRegion ep = vis.getStructureMap().getRegions(RegionType.ENTRY_POINT).get(0);
        // the whole file in a few rows: the entry point is one byte of a large cell
        ViewMapping mapping = new ViewMapping(vis.getFileLength(), 0,
                ViewMapping.fitBytesPerCell(vis.getFileLength(), 16, 16, true), 16);
        Viewport viewport = new Viewport(mapping, 0, (int) mapping.getRowCount(), 8);
        int[] argb = render(Track.STRUCTURE, vis, viewport, 8, RenderStyle.defaults().withAdditionalGap(2));
        assertEquals(pixelAt(argb, viewport, 8, ep.getStart()), vis.getColorScheme().rgbOf(ep));
        // the marker is inset, the border shows the region below
        java.awt.Point p = viewport.pixelOf(ep.getStart(), 8);
        assertNotEquals(argb[p.y * 16 * 8 + p.x], vis.getColorScheme().rgbOf(ep));
    }

    @Test
    public void largeMarkersAreOutlined() throws Exception {
        // an anomaly of WMIX.exe covers the whole overlay
        File file = sample("WMIX.exe");
        PEData data = PELoader.loadPE(file);
        StructureMap map = new StructureMapBuilder(data)
                .withAnomalies(PEAnomalyScanner.newInstance(data).getAnomalies()).build();
        FileRegion overlay = map.getRegions(RegionType.OVERLAY).get(0);
        FileRegion large = null;
        for (FileRegion anomaly : map.getRegions(RegionType.ANOMALY)) {
            if (anomaly.getStart() <= overlay.getStart() && anomaly.getEnd() >= overlay.getEnd()) {
                large = anomaly;
            }
        }
        assertNotNull(large, "no anomaly covers the overlay");
        RegionColorScheme scheme = RegionColorScheme.of(map);
        FileVisualization vis = new FileVisualization(map, new ByteStatistics(file), new CachedByteSource(file),
                scheme);
        ViewMapping mapping = new ViewMapping(file.length(), 0,
                ViewMapping.fitBytesPerCell(file.length(), 64, 1000, true), 64);
        // the middle of the overlay shows the overlay
        long middle = (overlay.getStart() + overlay.getEnd()) / 2;
        Viewport around = new Viewport(mapping, mapping.rowOf(middle) - 5, 10, 4);
        int[] argb = render(Track.STRUCTURE, vis, around, 4, RenderStyle.defaults());
        assertEquals(pixelAt(argb, around, 4, middle), scheme.rgbOf(overlay));
        // the first row of the anomaly has its outline at the top
        long start = large.getStart();
        Viewport top = new Viewport(mapping, mapping.rowOf(start), 3, 4);
        argb = render(Track.STRUCTURE, vis, top, 4, RenderStyle.defaults());
        java.awt.Point p = top.pixelOf(start, 4);
        int topEdge = argb[p.y * 64 * 4 + p.x + 2];
        boolean anomalyColor = false;
        for (FileRegion anomaly : map.regionsAt(start)) {
            if (anomaly.getType() == RegionType.ANOMALY && scheme.rgbOf(anomaly) == topEdge) {
                anomalyColor = true;
            }
        }
        assertTrue(anomalyColor, "the top edge of the anomaly is not outlined");
    }

    @Test
    public void typesThatAreNotPaintedAreSkipped() throws Exception {
        FileVisualization vis = visualization("WinRar.exe", false);
        ViewMapping mapping = new ViewMapping(vis.getFileLength(), 0, 1, 64);
        Viewport viewport = new Viewport(mapping, 0, 16, 2);
        RenderStyle style = RenderStyle.defaults().withPainted(RegionType.PE_SIGNATURE, false);
        int[] argb = render(Track.STRUCTURE, vis, viewport, 2, style);
        FileRegion peSig = vis.getStructureMap().getRegions(RegionType.PE_SIGNATURE).get(0);
        int coff = vis.getColorScheme().rgbOf(vis.getStructureMap().getRegions(RegionType.MSDOS_STUB).get(0));
        // without the signature the stub is not below it, the headers are not painted at all
        assertNotEquals(pixelAt(argb, viewport, 2, peSig.getStart()), vis.getColorScheme().rgbOf(peSig));
        assertNotEquals(pixelAt(argb, viewport, 2, peSig.getStart()), coff);
        assertEquals(pixelAt(argb, viewport, 2, peSig.getStart()), style.getBackground());
    }

    @Test
    public void tilesAreDeterministicAndSeamless() throws Exception {
        FileVisualization vis = visualization("WinRar.exe", true);
        ViewMapping mapping = new ViewMapping(vis.getFileLength(), 0, 32, 64);
        int rows = (int) Math.min(mapping.getRowCount(), 400);
        assertTrue(rows > 200);
        for (Track track : Track.values()) {
            for (RenderStyle style : Arrays.asList(RenderStyle.defaults(), RenderStyle.legacy())) {
                Viewport whole = new Viewport(mapping, 0, rows, 4);
                int[] all = render(track, vis, whole, 4, style);
                assertEquals(render(track, vis, whole, 4, style), all, track + " is not deterministic");
                int split = 123;
                int[] top = render(track, vis, new Viewport(mapping, 0, split, 4), 4, style);
                int[] bottom = render(track, vis, new Viewport(mapping, split, rows - split, 4), 4, style);
                int[] joined = Arrays.copyOf(top, all.length);
                System.arraycopy(bottom, 0, joined, top.length, bottom.length);
                assertEquals(joined, all, track + " " + style + " tiles differ from the whole image");
            }
        }
    }

    @Test
    public void legacyStylePaintsOnlyLegacyTypes() throws Exception {
        FileVisualization vis = visualization("WinRar.exe", false);
        ViewMapping mapping = new ViewMapping(vis.getFileLength(), 0, 1, 64);
        Viewport viewport = new Viewport(mapping, 0, 16, 2);
        int[] argb = render(Track.STRUCTURE, vis, viewport, 2, RenderStyle.legacy());
        StructureMap map = vis.getStructureMap();
        FileRegion peSig = map.getRegions(RegionType.PE_SIGNATURE).get(0);
        FileRegion stub = map.getRegions(RegionType.MSDOS_STUB).get(0);
        // the classic visualizer drew neither the stub nor the PE signature
        assertEquals(pixelAt(argb, viewport, 2, peSig.getStart()), RenderStyle.legacy().getBackground());
        assertEquals(pixelAt(argb, viewport, 2, stub.getStart() + 4), RenderStyle.legacy().getBackground());
        FileRegion msdos = map.getRegions(RegionType.MSDOS_HEADER).get(0);
        assertEquals(pixelAt(argb, viewport, 2, 0x10), vis.getColorScheme().rgbOf(msdos));
    }

    @Test
    public void legacyOrderDrawsResourcesLast() throws Exception {
        FileVisualization vis = visualization("WinRar.exe", false);
        StructureMap map = vis.getStructureMap();
        FileRegion resource = map.getRegions(RegionType.RESOURCE).get(0);
        ViewMapping mapping = new ViewMapping(vis.getFileLength(), 0, 1, 64);
        Viewport viewport = new Viewport(mapping, mapping.rowOf(resource.getStart()) + 1, 4, 4);
        int[] argb = render(Track.STRUCTURE, vis, viewport, 4, RenderStyle.legacy().withAdditionalGap(0));
        long offset = mapping.cellStart(viewport.getFirstRow(), 3);
        assertEquals(pixelAt(argb, viewport, 4, offset), vis.getColorScheme().rgbOf(resource));
    }

    @Test
    public void everyPaintedTypeHasAColor() throws Exception {
        FileVisualization vis = visualization("HelloWorld.exe", false);
        Set<Integer> colors = new HashSet<>();
        for (FileRegion region : vis.getStructureMap().getRegions()) {
            assertNotNull(vis.getColorScheme().colorOf(region));
            colors.add(vis.getColorScheme().rgbOf(region));
        }
        assertTrue(colors.size() > 5);
    }
}
