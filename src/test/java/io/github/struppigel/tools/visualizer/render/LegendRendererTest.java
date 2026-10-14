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
import io.github.struppigel.tools.layout.RegionType;
import io.github.struppigel.tools.layout.StructureMap;
import io.github.struppigel.tools.visualizer.engine.FileVisualization;
import org.testng.annotations.Test;

import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static io.github.struppigel.tools.visualizer.render.RenderTestSupport.visualization;
import static org.testng.Assert.*;

public class LegendRendererTest {

    private static List<String> labels(List<LegendEntry> entries) {
        List<String> labels = new ArrayList<>();
        for (LegendEntry entry : entries) {
            labels.add(entry.getLabel());
        }
        return labels;
    }

    @Test
    public void onlyPresentStructuresAreListed() throws Exception {
        FileVisualization hello = visualization("HelloWorld.exe", false);
        List<String> labels = labels(LegendRenderer.entries(hello.getStructureMap(), hello.getColorScheme(),
                false, false));
        assertTrue(labels.contains("PE Signature"), labels.toString());
        assertTrue(labels.contains("CLR Metadata"), labels.toString());
        assertTrue(labels.contains("#~"), labels.toString());
        assertTrue(labels.contains("RT_VERSION"), labels.toString());
        assertTrue(labels.contains("Entry Point"), labels.toString());
        assertFalse(labels.contains("Overlay"), labels.toString());
        assertFalse(labels.contains("Exports"), labels.toString());
        assertFalse(labels.contains("BytePlot"), labels.toString());

        FileVisualization overlay = visualization("embedded_exe_overlay", false);
        List<String> overlayLabels = labels(LegendRenderer.entries(overlay.getStructureMap(),
                overlay.getColorScheme(), true, true));
        assertTrue(overlayLabels.contains("Overlay"), overlayLabels.toString());
        assertTrue(overlayLabels.contains("BytePlot"));
        assertTrue(overlayLabels.contains("0.5 (code)"));
        assertFalse(overlayLabels.contains("Exports"), overlayLabels.toString());
    }

    @Test
    public void entriesUseTheSchemeColors() throws Exception {
        FileVisualization vis = visualization("WinRar.exe", false);
        for (LegendEntry entry : LegendRenderer.entries(vis.getStructureMap(), vis.getColorScheme(), true, true)) {
            if (entry.getLabel().equals("Overlay")) {
                assertEquals(entry.getColor(), vis.getColorScheme().colorOf(
                        vis.getStructureMap().getRegions(io.github.struppigel.tools.layout.RegionType.OVERLAY).get(0)));
            }
            if (entry.getLabel().equals(".text")) {
                assertEquals(entry.getColor(), vis.getColorScheme().colorOf(
                        vis.getStructureMap().getRegions(io.github.struppigel.tools.layout.RegionType.SECTION).get(0)));
            }
        }
    }

    @Test
    public void entriesKnowTheirStructures() throws Exception {
        FileVisualization vis = visualization("HelloWorld.exe", false);
        StructureMap map = vis.getStructureMap();
        List<LegendEntry> entries = LegendRenderer.entries(map, vis.getColorScheme(), true, true);
        for (LegendEntry entry : entries) {
            if (entry.isTitle() || entry.getLabel().equals("0xFF") || entry.getLabel().contains("ASCII")
                    || entry.getLabel().contains("(")) {
                assertTrue(entry.getRegions().isEmpty(), entry.toString());
            }
            if (entry.getLabel().equals(".text")) {
                assertEquals(entry.getRegions().size(), 1);
                assertEquals(entry.getRegions().get(0).getType(), RegionType.SECTION);
            }
            if (entry.getLabel().equals("RT_VERSION")) {
                assertFalse(entry.getRegions().isEmpty());
                for (FileRegion region : entry.getRegions()) {
                    assertEquals(region.getType(), RegionType.RESOURCE);
                    assertEquals(region.getAttributes().get(FileRegion.ATTR_RESOURCE_TYPE), "RT_VERSION");
                }
            }
            if (entry.getLabel().equals("#~")) {
                assertFalse(entry.getRegions().isEmpty());
                for (FileRegion region : entry.getRegions()) {
                    assertEquals(region.getName(), "#~");
                }
            }
            if (entry.getLabel().equals("PE Signature")) {
                assertEquals(entry.getRegions().size(), map.getRegions(RegionType.PE_SIGNATURE).size());
            }
        }
    }

    @Test
    public void everyStructureEntryHasStructures() throws Exception {
        FileVisualization vis = visualization("WinRar.exe", false);
        for (LegendEntry entry : LegendRenderer.entries(vis.getStructureMap(), vis.getColorScheme(), false, false,
                EnumSet.allOf(RegionType.class))) {
            if (!entry.isTitle()) {
                assertFalse(entry.getRegions().isEmpty(), entry.toString());
            }
        }
    }

    @Test
    public void emptyMapHasOnlyPlotEntries() {
        StructureMap map = StructureMap.empty(100);
        List<LegendEntry> entries = LegendRenderer.entries(map, RegionColorScheme.of(map), true, true);
        assertEquals(entries.size(), 10);
        assertFalse(labels(entries).contains("PE Structure"));
    }

    @Test
    public void fittedLegendShowsWholeLabels() throws Exception {
        FileVisualization vis = visualization("WinRar.exe", false);
        List<LegendEntry> entries = LegendRenderer.entries(vis.getStructureMap(), vis.getColorScheme(), true, true);
        java.awt.FontMetrics metrics = new BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB).createGraphics()
                .getFontMetrics();
        for (int height : new int[]{200, 280, 1000}) {
            BufferedImage image = LegendRenderer.renderFitted(entries, height);
            assertEquals(image.getHeight(), height);
            assertEquals(image.getWidth(), LegendRenderer.fittedWidth(entries, height));
            int rows = (height - 10) / 20;
            int columns = (entries.size() + rows - 1) / rows;
            int columnWidth = image.getWidth() / columns;
            for (LegendEntry entry : entries) {
                // gap, sample, gap, label, gap
                int needed = 10 + (entry.isTitle() ? 0 : 20) + metrics.stringWidth(entry.getLabel()) + 10;
                assertTrue(columnWidth >= needed, entry + " needs " + needed + " but the column has " + columnWidth);
            }
            // the first entry of the last column is drawn
            int last = (columns - 1) * rows;
            if (!entries.get(last).isTitle()) {
                assertEquals(image.getRGB((columns - 1) * columnWidth + 10 + 5, 10 + 5) & 0xFFFFFF,
                        entries.get(last).getColor().getRGB() & 0xFFFFFF);
            }
        }
    }

    @Test
    public void rendersTwoColumns() throws Exception {
        FileVisualization vis = visualization("WinRar.exe", false);
        List<LegendEntry> entries = LegendRenderer.entries(vis.getStructureMap(), vis.getColorScheme(), true, true);
        BufferedImage image = LegendRenderer.render(entries, 300, 200);
        assertEquals(image.getWidth(), 300);
        assertEquals(image.getHeight(), 200);
        // entry 10 is the first one of the second column at x = 160, it is a title; entry 11 follows at y = 30
        assertTrue(entries.get(10).isTitle());
        LegendEntry second = entries.get(11);
        assertFalse(second.isTitle());
        assertEquals(image.getRGB(160 + 5, 30 + 5) & 0xFFFFFF, second.getColor().getRGB() & 0xFFFFFF);
    }
}
