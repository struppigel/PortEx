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
import io.github.struppigel.tools.visualizer.ColorableItem;
import io.github.struppigel.tools.visualizer.VisualizerBuilder;
import io.github.struppigel.tools.visualizer.engine.ByteClass;

import java.awt.Color;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * The colors of the regions of one structure map.
 * <p>
 * Colors are computed once when the scheme is created, so they do not depend
 * on drawing order:
 * <ul>
 * <li>base colors come from the {@link ColorableItem} colors, e.g. of a
 * {@link VisualizerBuilder}</li>
 * <li>sections are shaded by their number like in the classic visualizer</li>
 * <li>regions inside a region of the same color are alternating shades of it,
 * e.g. the DLLs of the imports</li>
 * <li>{@link Mode#DEFAULT}: resource types have fixed colors that are the same
 * for every file, .NET streams are colored by name</li>
 * <li>{@link Mode#LEGACY}: resource types and .NET streams are colored in order
 * of appearance like in the classic visualizer</li>
 * </ul>
 * Use {@link #colorOf(FileRegion)} to show the same colors elsewhere, e.g. in
 * a legend or an info pane. Instances are immutable.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class RegionColorScheme {

    /** how resources and streams are colored */
    public enum Mode {
        /** fixed colors per resource type and stream name */
        DEFAULT,
        /** colors in order of appearance, like the classic visualizer */
        LEGACY
    }

    private static final Color FALLBACK = new Color(128, 128, 128);
    private static final Color LEGACY_RESOURCE_START = new Color(220, 255, 220);
    private static final String[] RESOURCE_TYPES = {"RT_CURSOR", "RT_BITMAP", "RT_ICON", "RT_MENU", "RT_DIALOG",
            "RT_STRING", "RT_FONTDIR", "RT_FONT", "RT_ACCELERATOR", "RT_RCDATA", "RT_MESSAGETABLE",
            "RT_GROUP_CURSOR", "RT_GROUP_ICON", "RT_VERSION", "RT_DLGINCLUDE", "RT_PLUGPLAY", "RT_VXD",
            "RT_ANICURSOR", "RT_ANIICON", "RT_HTML", "RT_MANIFEST"};
    private static final String[] STREAMS = {"#~", "#Strings", "#US", "#GUID", "#Blob", "#-"};

    private final StructureMap map;
    private final Mode mode;
    private final Map<ColorableItem, Color> colors;
    private final int[] rgbById;
    private final Map<String, Color> resourceTypeColors;
    private final int[] bytePlotPalette = new int[256];
    private final float[] entropyHsb;

    private RegionColorScheme(StructureMap map, Map<ColorableItem, Color> colorMap, Mode mode) {
        this.map = map;
        this.mode = mode;
        Map<ColorableItem, Color> copy = new EnumMap<>(ColorableItem.class);
        copy.putAll(VisualizerBuilder.getDefaultColors());
        for (Map.Entry<ColorableItem, Color> e : colorMap.entrySet()) {
            if (e.getValue() != null) {
                copy.put(e.getKey(), e.getValue());
            }
        }
        this.colors = Collections.unmodifiableMap(copy);
        this.resourceTypeColors = new LinkedHashMap<>();
        this.rgbById = new int[map.getRegions().size()];
        Map<FileRegion, Integer> shadeIndex = new HashMap<>();
        int streamIndex = 0;
        Color legacyResource = LEGACY_RESOURCE_START;
        for (FileRegion region : map.getRegions()) {
            Color color;
            if (region.getType() == RegionType.RESOURCE) {
                String type = region.getAttributes().get(FileRegion.ATTR_RESOURCE_TYPE);
                String key = type == null ? "" : type;
                color = resourceTypeColors.get(key);
                if (color == null) {
                    if (mode == Mode.LEGACY) {
                        color = legacyResource;
                        legacyResource = VisualizerColors.variate(legacyResource, colorOf(ColorableItem.SECTION_START));
                    } else {
                        color = fixedResourceColor(key);
                    }
                    resourceTypeColors.put(key, color);
                }
            } else if (region.getType() == RegionType.CLR_STREAM && mode == Mode.LEGACY) {
                color = VisualizerColors.variate(colorOf(ColorableItem.NET_STREAMS),
                        colorOf(ColorableItem.SECTION_START), streamIndex++);
            } else if (region.getType() == RegionType.CLR_STREAM) {
                color = streamColor(region.getAttributes().get(FileRegion.ATTR_STREAM_NAME));
            } else if (region.getType() == RegionType.SECTION) {
                color = sectionColor(region);
            } else {
                color = baseColor(region);
                FileRegion parent = region.getParent().orElse(null);
                if (mode == Mode.DEFAULT && parent != null && parent.getType().getColorableItem() != null
                        && parent.getType().getColorableItem() == region.getType().getColorableItem()) {
                    // alternating shades of the parent color
                    int index = shadeIndex.containsKey(parent) ? shadeIndex.get(parent) : 0;
                    shadeIndex.put(parent, index + 1);
                    Color parentColor = new Color(rgbById[parent.getId()]);
                    color = VisualizerColors.shade(parentColor, index % 2 == 0 ? 0.25 : -0.2);
                }
            }
            rgbById[region.getId()] = 0xFF000000 | color.getRGB();
        }
        for (int b = 0; b < 256; b++) {
            bytePlotPalette[b] = 0xFF000000 | VisualizerColors.bytePlotColor(b, colorOf(ColorableItem.MIN_BYTE),
                    colorOf(ColorableItem.MAX_BYTE), colorOf(ColorableItem.VISIBLE_ASCII),
                    colorOf(ColorableItem.INVISIBLE_ASCII), colorOf(ColorableItem.NON_ASCII)).getRGB();
        }
        this.entropyHsb = VisualizerColors.hsb(colorOf(ColorableItem.ENTROPY));
    }

    /**
     * Creates the scheme of a structure map with the default colors.
     *
     * @param map the structure map
     * @return the color scheme
     */
    public static RegionColorScheme of(StructureMap map) {
        return of(map, VisualizerBuilder.getDefaultColors(), Mode.DEFAULT);
    }

    /**
     * Creates the scheme of a structure map.
     *
     * @param map the structure map
     * @param colors the colors of the colorable items, missing items get their default color
     * @param mode how resources and streams are colored
     * @return the color scheme
     */
    public static RegionColorScheme of(StructureMap map, Map<ColorableItem, Color> colors, Mode mode) {
        return new RegionColorScheme(Objects.requireNonNull(map), Objects.requireNonNull(colors),
                Objects.requireNonNull(mode));
    }

    private Color baseColor(FileRegion region) {
        ColorableItem item = region.getType().getColorableItem();
        if (item != null) {
            return colorOf(item);
        }
        FileRegion parent = region.getParent().orElse(null);
        return parent != null ? new Color(rgbById[parent.getId()]) : FALLBACK;
    }

    private Color sectionColor(FileRegion region) {
        int number = 1;
        try {
            number = Integer.parseInt(region.getAttributes().get(FileRegion.ATTR_SECTION_NUMBER));
        } catch (NumberFormatException e) {
            // keep the first color
        }
        Color start = colorOf(ColorableItem.SECTION_START);
        return VisualizerColors.variate(start, start, Math.max(0, number - 1));
    }

    private Color fixedResourceColor(String type) {
        for (int i = 0; i < RESOURCE_TYPES.length; i++) {
            if (RESOURCE_TYPES[i].equals(type)) {
                float hue = (float) ((0.33 + i * 0.618034) % 1.0);
                return Color.getHSBColor(hue, 0.45f, 0.95f);
            }
        }
        float hue = (type.hashCode() & 0xFFFF) / (float) 0x10000;
        return Color.getHSBColor(hue, 0.25f, 0.8f);
    }

    private Color streamColor(String name) {
        Color base = colorOf(ColorableItem.NET_STREAMS);
        for (int i = 0; i < STREAMS.length; i++) {
            if (STREAMS[i].equals(name)) {
                return VisualizerColors.shade(base, i % 2 == 0 ? -0.1 * (i / 2) : 0.4 - 0.1 * (i / 2));
            }
        }
        return VisualizerColors.shade(base, -0.4);
    }

    /**
     * @return the structure map of this scheme
     */
    public StructureMap getStructureMap() {
        return map;
    }

    /**
     * @return the mode of this scheme
     */
    public Mode getMode() {
        return mode;
    }

    /**
     * @return the colors of all colorable items
     */
    public Map<ColorableItem, Color> getColors() {
        return colors;
    }

    /**
     * @param item a colorable item
     * @return the color of the item, never null
     */
    public Color colorOf(ColorableItem item) {
        Color color = colors.get(item);
        return color != null ? color : FALLBACK;
    }

    /**
     * Returns the color of a region of the structure map of this scheme.
     *
     * @param region a region
     * @return the color of the region, never null
     */
    public Color colorOf(FileRegion region) {
        return new Color(rgbOf(region));
    }

    /**
     * Returns the color of a region as opaque ARGB int.
     *
     * @param region a region
     * @return the color of the region
     */
    public int rgbOf(FileRegion region) {
        int id = region.getId();
        if (id >= 0 && id < rgbById.length && map.getRegions().get(id) == region) {
            return rgbById[id];
        }
        return 0xFF000000 | baseColor(region).getRGB();
    }

    /**
     * @return the color of each resource type of the map in order of appearance
     */
    public Map<String, Color> getResourceTypeColors() {
        return Collections.unmodifiableMap(resourceTypeColors);
    }

    /**
     * @param value a byte value
     * @return the byte plot color of the value as opaque ARGB int
     */
    public int bytePlotRgb(int value) {
        return bytePlotPalette[value & 0xFF];
    }

    /**
     * @param byteClass a byte class
     * @param meanValue the mean value of the bytes of the class
     * @return the byte plot color of the class as opaque ARGB int
     */
    public int classRgb(ByteClass byteClass, double meanValue) {
        return 0xFF000000 | VisualizerColors.classColor(byteClass, meanValue, colorOf(ColorableItem.MIN_BYTE),
                colorOf(ColorableItem.MAX_BYTE), colorOf(ColorableItem.VISIBLE_ASCII),
                colorOf(ColorableItem.INVISIBLE_ASCII), colorOf(ColorableItem.NON_ASCII)).getRGB();
    }

    /**
     * @param entropy an entropy from 0 to 1
     * @return the entropy color as opaque ARGB int
     */
    public int entropyRgb(double entropy) {
        return VisualizerColors.entropyRgb(entropyHsb, entropy);
    }
}
