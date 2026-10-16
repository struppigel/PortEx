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
import io.github.struppigel.tools.visualizer.ColorableItem;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Creates legends. The entries only depend on the structure map and the color
 * scheme, so the legend is the same however the tracks were drawn before.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class LegendRenderer {

    /**
     * title of the structure entries, also used for files that are no PE
     * files, whose structures are signature matches and custom regions
     */
    public static final String STRUCTURE_TITLE = "Structure";

    private static final int SAMPLE_SIZE = 10;
    private static final int GAP = 10;
    private static final int ENTRY_HEIGHT = 20;

    private LegendRenderer() {
    }

    /**
     * Returns the legend entries of the byte plot, the entropy and the
     * structures present in the map. Each section, resource type and .NET
     * stream gets its own entry; other regions get one entry per color. Types
     * that are never drawn are left out.
     *
     * @param map the structure map
     * @param scheme the colors
     * @param byteplot true to add the byte plot entries
     * @param entropy true to add the entropy entries
     * @return the legend entries
     */
    public static List<LegendEntry> entries(StructureMap map, RegionColorScheme scheme, boolean byteplot,
                                            boolean entropy) {
        return entries(map, scheme, byteplot, entropy, RenderStyle.defaults().getPaintedTypes());
    }

    /**
     * Returns the legend entries like {@link #entries(StructureMap, RegionColorScheme, boolean, boolean)},
     * but only for structures of the painted types, e.g. of
     * {@link RenderStyle#getPaintedTypes()}.
     *
     * @param map the structure map
     * @param scheme the colors
     * @param byteplot true to add the byte plot entries
     * @param entropy true to add the entropy entries
     * @param paintedTypes the types that are drawn
     * @return the legend entries
     */
    public static List<LegendEntry> entries(StructureMap map, RegionColorScheme scheme, boolean byteplot,
                                            boolean entropy, Set<RegionType> paintedTypes) {
        List<LegendEntry> entries = new ArrayList<>();
        if (byteplot) {
            entries.addAll(bytePlotEntries(scheme));
        }
        if (entropy) {
            entries.addAll(entropyEntries(scheme));
        }
        List<LegendEntry> structure = structureEntries(map, scheme, paintedTypes);
        if (!structure.isEmpty()) {
            entries.add(LegendEntry.title(STRUCTURE_TITLE));
            entries.addAll(structure);
        }
        return Collections.unmodifiableList(entries);
    }

    /**
     * @param scheme the colors
     * @return the title and entries of the byte plot
     */
    public static List<LegendEntry> bytePlotEntries(RegionColorScheme scheme) {
        List<LegendEntry> entries = new ArrayList<>();
        entries.add(LegendEntry.title("BytePlot"));
        entries.add(LegendEntry.entry("0xFF", scheme.colorOf(ColorableItem.MAX_BYTE), false));
        entries.add(LegendEntry.entry("0x00", scheme.colorOf(ColorableItem.MIN_BYTE), false));
        entries.add(LegendEntry.entry("visible ASCII", scheme.colorOf(ColorableItem.VISIBLE_ASCII), false));
        entries.add(LegendEntry.entry("invisible ASCII", scheme.colorOf(ColorableItem.INVISIBLE_ASCII), false));
        entries.add(LegendEntry.entry("non-ASCII", scheme.colorOf(ColorableItem.NON_ASCII), false));
        return entries;
    }

    /**
     * @param scheme the colors
     * @return the title and entries of the entropy
     */
    public static List<LegendEntry> entropyEntries(RegionColorScheme scheme) {
        List<LegendEntry> entries = new ArrayList<>();
        entries.add(LegendEntry.title("Entropy"));
        entries.add(LegendEntry.entry("0.2 (repetition)", new Color(scheme.entropyRgb(0.2)), false));
        entries.add(LegendEntry.entry("0.5 (code)", new Color(scheme.entropyRgb(0.5)), false));
        entries.add(LegendEntry.entry("0.8 (packed)", new Color(scheme.entropyRgb(0.8)), false));
        return entries;
    }

    private static List<LegendEntry> structureEntries(StructureMap map, RegionColorScheme scheme,
                                                      Set<RegionType> paintedTypes) {
        List<LegendEntry> entries = new ArrayList<>();
        Set<ColorableItem> listed = EnumSet.noneOf(ColorableItem.class);
        for (RegionType type : RegionType.values()) {
            if (type.getPaintMode() == PaintMode.NONE || !paintedTypes.contains(type)) {
                continue;
            }
            List<FileRegion> regions = map.getRegions(type);
            if (regions.isEmpty()) {
                continue;
            }
            boolean outlined = type.getPaintMode() != PaintMode.FILL;
            if (type == RegionType.SECTION) {
                for (FileRegion section : regions) {
                    String name = section.getAttributes().get(FileRegion.ATTR_SECTION_NAME);
                    entries.add(LegendEntry.entry(name == null || name.isEmpty() ? section.getName() : name,
                            scheme.colorOf(section), false, Collections.singletonList(section)));
                }
            } else if (type == RegionType.RESOURCE) {
                Map<String, List<FileRegion>> byType = new LinkedHashMap<>();
                for (FileRegion resource : regions) {
                    String resourceType = resource.getAttributes().get(FileRegion.ATTR_RESOURCE_TYPE);
                    String key = resourceType == null ? "" : resourceType;
                    List<FileRegion> sameType = byType.get(key);
                    if (sameType == null) {
                        sameType = new ArrayList<>();
                        byType.put(key, sameType);
                    }
                    sameType.add(resource);
                }
                for (Map.Entry<String, Color> e : scheme.getResourceTypeColors().entrySet()) {
                    List<FileRegion> sameType = byType.get(e.getKey());
                    entries.add(LegendEntry.entry(e.getKey(), e.getValue(), outlined,
                            sameType == null ? Collections.<FileRegion>emptyList() : sameType));
                }
            } else if (type == RegionType.CLR_STREAM) {
                Map<String, Color> streams = new LinkedHashMap<>();
                Map<String, List<FileRegion>> streamRegions = new LinkedHashMap<>();
                for (FileRegion stream : regions) {
                    if (!streams.containsKey(stream.getName())) {
                        streams.put(stream.getName(), scheme.colorOf(stream));
                        streamRegions.put(stream.getName(), new ArrayList<FileRegion>());
                    }
                    streamRegions.get(stream.getName()).add(stream);
                }
                for (Map.Entry<String, Color> e : streams.entrySet()) {
                    entries.add(LegendEntry.entry(e.getKey(), e.getValue(), outlined, streamRegions.get(e.getKey())));
                }
            } else {
                ColorableItem item = type.getColorableItem();
                if (item == null || listed.contains(item)) {
                    continue;
                }
                listed.add(item);
                entries.add(LegendEntry.entry(item.getLegendDescription(), scheme.colorOf(item), outlined,
                        regionsOfItem(map, item, paintedTypes)));
            }
        }
        return entries;
    }

    /**
     * @return the structures of all painted types that share the color of the item, except the types that have
     *         entries of their own
     */
    private static List<FileRegion> regionsOfItem(StructureMap map, ColorableItem item, Set<RegionType> paintedTypes) {
        List<FileRegion> result = new ArrayList<>();
        for (RegionType type : RegionType.values()) {
            if (type == RegionType.SECTION || type == RegionType.RESOURCE || type == RegionType.CLR_STREAM
                    || type.getPaintMode() == PaintMode.NONE || !paintedTypes.contains(type)
                    || type.getColorableItem() != item) {
                continue;
            }
            result.addAll(map.getRegions(type));
        }
        return result;
    }

    /**
     * Returns the width that {@link #renderFitted(List, int)} needs to show
     * all labels in full.
     *
     * @param entries the entries
     * @param height the height of the legend
     * @return the width of the fitted legend in pixels
     */
    public static int fittedWidth(List<LegendEntry> entries, int height) {
        return columnCount(entries, height) * columnWidth(entries);
    }

    /**
     * Draws a legend whose width fits its labels: one entry per row of 20
     * pixels with a 10 pixel color sample and white text, in as many columns
     * as the height needs. Titles are underlined.
     *
     * @param entries the entries
     * @param height the height of the image
     * @return the legend image, {@link #fittedWidth(List, int)} pixels wide
     */
    public static BufferedImage renderFitted(List<LegendEntry> entries, int height) {
        int rows = rowsPerColumn(height);
        int columnWidth = columnWidth(entries);
        BufferedImage image = new BufferedImage(Math.max(1, fittedWidth(entries, height)), Math.max(1, height),
                BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        try {
            for (int i = 0; i < entries.size(); i++) {
                LegendEntry entry = entries.get(i);
                int x = (i / rows) * columnWidth + GAP;
                int y = GAP + (i % rows) * ENTRY_HEIGHT;
                if (entry.isTitle()) {
                    g.setColor(entry.getColor());
                    g.drawString(entry.getLabel(), x, y + SAMPLE_SIZE);
                    g.drawLine(x, y + SAMPLE_SIZE + 4, x + columnWidth - 2 * GAP, y + SAMPLE_SIZE + 4);
                } else {
                    drawEntry(g, entry, x, y);
                }
            }
        } finally {
            g.dispose();
        }
        return image;
    }

    private static int rowsPerColumn(int height) {
        return Math.max(1, (height - GAP) / ENTRY_HEIGHT);
    }

    private static int columnCount(List<LegendEntry> entries, int height) {
        int rows = rowsPerColumn(height);
        return Math.max(1, (entries.size() + rows - 1) / rows);
    }

    /** the widest label with its sample and gaps */
    private static int columnWidth(List<LegendEntry> entries) {
        BufferedImage scratch = new BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = scratch.createGraphics();
        try {
            java.awt.FontMetrics metrics = g.getFontMetrics();
            int widest = 0;
            for (LegendEntry entry : entries) {
                int label = metrics.stringWidth(entry.getLabel());
                widest = Math.max(widest, entry.isTitle() ? label : SAMPLE_SIZE + GAP + label);
            }
            return GAP + widest + GAP;
        } finally {
            g.dispose();
        }
    }

    private static void drawEntry(Graphics2D g, LegendEntry entry, int x, int y) {
        g.setColor(entry.getColor());
        g.fillRect(x, y, SAMPLE_SIZE, SAMPLE_SIZE);
        if (entry.isOutlined()) {
            g.setColor(Color.black);
            g.drawRect(x + 1, y + 1, SAMPLE_SIZE - 3, SAMPLE_SIZE - 3);
        }
        g.setColor(Color.white);
        g.drawString(entry.getLabel(), x + SAMPLE_SIZE + GAP, y + SAMPLE_SIZE);
    }

    /**
     * Draws a legend like the classic visualizer: one entry per row of 20
     * pixels with a 10 pixel color sample and white text. Entries that do not
     * fit the height continue in a second column at half the width; long
     * labels may be cut. See {@link #renderFitted(List, int)} for a legend
     * that fits its labels.
     *
     * @param entries the entries
     * @param width the width of the image
     * @param height the height of the image
     * @return the legend image
     */
    public static BufferedImage render(List<LegendEntry> entries, int width, int height) {
        BufferedImage image = new BufferedImage(Math.max(1, width), Math.max(1, height), BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        try {
            int number = 0;
            for (LegendEntry entry : entries) {
                int x = GAP;
                int y = GAP + ENTRY_HEIGHT * number++;
                if (y >= height) {
                    x += width / 2;
                    y -= height;
                }
                if (entry.isTitle()) {
                    g.setColor(entry.getColor());
                    g.drawString(entry.getLabel(), x, y + SAMPLE_SIZE);
                    g.drawString("---------------------------------", x, y + 2 * SAMPLE_SIZE);
                } else {
                    g.setColor(entry.getColor());
                    g.fillRect(x, y, SAMPLE_SIZE, SAMPLE_SIZE);
                    if (entry.isOutlined()) {
                        g.setColor(Color.black);
                        g.drawRect(x + 1, y + 1, SAMPLE_SIZE - 3, SAMPLE_SIZE - 3);
                    }
                    g.setColor(Color.white);
                    g.drawString(entry.getLabel(), x + SAMPLE_SIZE + GAP, y + SAMPLE_SIZE);
                }
            }
        } finally {
            g.dispose();
        }
        return image;
    }
}
