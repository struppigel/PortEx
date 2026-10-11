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

import io.github.struppigel.tools.layout.PaintMode;
import io.github.struppigel.tools.layout.RegionType;

import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * How the renderers draw a visualization.
 * <p>
 * {@link #defaults()} is the look of the interactive visualization,
 * {@link #legacy()} reproduces the classic
 * {@link io.github.struppigel.tools.visualizer.Visualizer} images. Styles are
 * immutable; the with* methods return changed copies. Equal styles render
 * equal images, so a style can be part of a tile cache key.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class RenderStyle {

    /** how the byte plot colors a cell that covers several bytes */
    public enum ByteplotMode {
        /** the most frequent byte class at the mean value of its bytes */
        DOMINANT,
        /** the mean color of all bytes */
        AVERAGE,
        /** the color of one sampled byte, the first byte of the cell by default */
        FIRST_BYTE
    }

    /** which entropy the entropy track shows */
    public enum EntropyMode {
        /** the mean entropy of the 256 byte windows of the cell */
        MEAN,
        /** the highest entropy of a 256 byte window of the cell */
        MAX,
        /** the entropy of one window around a sampled byte, as the classic visualizer */
        LEGACY_WINDOW
    }

    /** which cells a structure covers */
    public enum CellRule {
        /** the cells whose middle byte belongs to the structure */
        MIDPOINT,
        /** the cells from the first to the last byte of the structure, rounded down, as the classic visualizer */
        FLOOR
    }

    /** in which order structures are drawn on top of each other */
    public enum Layering {
        /** more specific (smaller) structures on top */
        SPECIFICITY,
        /** the fixed order of the classic visualizer */
        LEGACY_ORDER
    }

    private static final Set<RegionType> LEGACY_TYPES = Collections.unmodifiableSet(EnumSet.of(
            RegionType.SECTION, RegionType.OVERLAY, RegionType.MSDOS_HEADER, RegionType.RICH_HEADER,
            RegionType.CLR_HEADER, RegionType.METADATA_ROOT, RegionType.CLR_STREAM, RegionType.OPTIONAL_HEADER,
            RegionType.COFF_FILE_HEADER, RegionType.SECTION_TABLE, RegionType.RESOURCE_DIRECTORY,
            RegionType.IMPORT_SECTION, RegionType.DELAY_IMPORT_SECTION, RegionType.EXPORT_SECTION,
            RegionType.RELOCATION, RegionType.DEBUG_DIRECTORY, RegionType.CODEVIEW, RegionType.ENTRY_POINT,
            RegionType.CUSTOM, RegionType.RESOURCE));

    private static final int BLACK = 0xFF000000;
    private static final int HATCH = 0xFF3A3A3A;

    private final ByteplotMode byteplotMode;
    private final EntropyMode entropyMode;
    private final CellRule cellRule;
    private final Layering layering;
    private final Set<RegionType> paintedTypes;
    private final int additionalGap;
    private final boolean pixelated;
    private final double minimumRegionLength;
    private final long sampleStep;
    private final int legacyEntropyWindow;
    private final int background;
    private final int hatchColor;
    private final boolean hatchPending;
    private final Track hexBackground;
    private final String hexFontFamily;
    private final boolean hexText;

    /** font families for hex cells, the first installed one is the default */
    private static final String[] PREFERRED_HEX_FONTS = {"Consolas", "Menlo", "DejaVu Sans Mono"};

    /** the installed font families, read once on first use */
    private static final class InstalledFonts {
        static final Map<String, String> BY_LOWER_CASE_NAME = new HashMap<>();
        static final String DEFAULT_HEX_FONT;

        static {
            for (String name : GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames()) {
                BY_LOWER_CASE_NAME.put(name.toLowerCase(Locale.ROOT), name);
            }
            String family = Font.MONOSPACED;
            for (String preferred : PREFERRED_HEX_FONTS) {
                if (BY_LOWER_CASE_NAME.containsKey(preferred.toLowerCase(Locale.ROOT))) {
                    family = BY_LOWER_CASE_NAME.get(preferred.toLowerCase(Locale.ROOT));
                    break;
                }
            }
            DEFAULT_HEX_FONT = family;
        }
    }

    private RenderStyle(ByteplotMode byteplotMode, EntropyMode entropyMode, CellRule cellRule, Layering layering,
                        Set<RegionType> paintedTypes, int additionalGap, boolean pixelated,
                        double minimumRegionLength, long sampleStep, int legacyEntropyWindow, int background,
                        int hatchColor, boolean hatchPending, Track hexBackground, String hexFontFamily,
                        boolean hexText) {
        if (additionalGap < 0 || minimumRegionLength < 0 || sampleStep < 0 || legacyEntropyWindow < 1) {
            throw new IllegalArgumentException("invalid render style value");
        }
        if (hexBackground == Track.HEX || hexBackground == Track.ASCII) {
            throw new IllegalArgumentException("the hex background must be a structure, byte plot or entropy track");
        }
        this.hexBackground = Objects.requireNonNull(hexBackground);
        this.hexFontFamily = Objects.requireNonNull(hexFontFamily);
        this.hexText = hexText;
        this.byteplotMode = Objects.requireNonNull(byteplotMode);
        this.entropyMode = Objects.requireNonNull(entropyMode);
        this.cellRule = Objects.requireNonNull(cellRule);
        this.layering = Objects.requireNonNull(layering);
        this.paintedTypes = paintedTypes.isEmpty() ? Collections.<RegionType>emptySet()
                : Collections.unmodifiableSet(EnumSet.copyOf(paintedTypes));
        this.additionalGap = additionalGap;
        this.pixelated = pixelated;
        this.minimumRegionLength = minimumRegionLength;
        this.sampleStep = sampleStep;
        this.legacyEntropyWindow = legacyEntropyWindow;
        this.background = background;
        this.hatchColor = hatchColor;
        this.hatchPending = hatchPending;
    }

    /**
     * The interactive look: dominant byte classes, mean window entropy,
     * midpoint cells, specificity layering and all structure types.
     *
     * @return the default style
     */
    public static RenderStyle defaults() {
        Set<RegionType> types = EnumSet.noneOf(RegionType.class);
        for (RegionType type : RegionType.values()) {
            if (type.getPaintMode() != PaintMode.NONE) {
                types.add(type);
            }
        }
        return new RenderStyle(ByteplotMode.DOMINANT, EntropyMode.MEAN, CellRule.MIDPOINT, Layering.SPECIFICITY,
                types, 1, false, 0, 0, 100, BLACK, HATCH, true, Track.STRUCTURE, defaultHexFontFamily(), true);
    }

    /**
     * The look of the classic visualizer: one sampled byte per cell, the
     * entropy of a window of 100 bytes, rounded down cell ranges, the fixed
     * drawing order and only the structures the classic visualizer drew.
     *
     * @return the legacy style
     */
    public static RenderStyle legacy() {
        return new RenderStyle(ByteplotMode.FIRST_BYTE, EntropyMode.LEGACY_WINDOW, CellRule.FLOOR,
                Layering.LEGACY_ORDER, LEGACY_TYPES, 1, false, 0, 0, 100, BLACK, HATCH, true, Track.STRUCTURE,
                defaultHexFontFamily(), true);
    }

    /**
     * Returns the default font family of hex and ASCII cells: the first
     * installed one of Consolas, Menlo and DejaVu Sans Mono, else the logical
     * font {@link Font#MONOSPACED}.
     *
     * @return the default font family
     */
    public static String defaultHexFontFamily() {
        return InstalledFonts.DEFAULT_HEX_FONT;
    }

    /**
     * @return the types the classic visualizer drew
     */
    public static Set<RegionType> legacyTypes() {
        return LEGACY_TYPES;
    }

    public ByteplotMode getByteplotMode() {
        return byteplotMode;
    }

    public EntropyMode getEntropyMode() {
        return entropyMode;
    }

    public CellRule getCellRule() {
        return cellRule;
    }

    public Layering getLayering() {
        return layering;
    }

    /**
     * @return the region types the structure renderer draws
     */
    public Set<RegionType> getPaintedTypes() {
        return paintedTypes;
    }

    /**
     * @param type a region type
     * @return true if the structure renderer draws regions of the type
     */
    public boolean paints(RegionType type) {
        return type.getPaintMode() != PaintMode.NONE && paintedTypes.contains(type);
    }

    /**
     * @return the inset in pixels of inset and marker cells
     */
    public int getAdditionalGap() {
        return additionalGap;
    }

    /**
     * @return true if every cell has a border
     */
    public boolean isPixelated() {
        return pixelated;
    }

    /**
     * Returns the minimum length of a structure for the {@link CellRule#FLOOR}
     * rule. Shorter structures except sections are extended to the rounded
     * minimum, as the classic visualizer did. 0 turns this off.
     *
     * @return the minimum length in bytes
     */
    public double getMinimumRegionLength() {
        return minimumRegionLength;
    }

    /**
     * Returns the step between sampled bytes of {@link ByteplotMode#FIRST_BYTE}
     * and {@link EntropyMode#LEGACY_WINDOW}. A cell shows the last sample
     * before its end. 0 samples the first byte of each cell.
     *
     * @return the sample step in bytes
     */
    public long getSampleStep() {
        return sampleStep;
    }

    /**
     * @return the window size of {@link EntropyMode#LEGACY_WINDOW}
     */
    public int getLegacyEntropyWindow() {
        return legacyEntropyWindow;
    }

    /**
     * @return the background color as ARGB
     */
    public int getBackground() {
        return background;
    }

    /**
     * @return the color of the hatch pattern of cells whose statistics are pending
     */
    public int getHatchColor() {
        return hatchColor;
    }

    /**
     * @return true if cells whose statistics are not computed yet are hatched
     */
    public boolean isHatchPending() {
        return hatchPending;
    }

    /**
     * Returns the track whose colors the hex and ASCII tracks use as cell
     * background: {@link Track#STRUCTURE} (the default), {@link Track#BYTEPLOT}
     * or {@link Track#ENTROPY}. Structure colors are lightened if they are
     * dark, byte plot and entropy colors are used exactly as in their tracks.
     *
     * @return the background track of hex and ASCII cells
     */
    public Track getHexBackground() {
        return hexBackground;
    }

    /**
     * @return the installed font family of the hex and ASCII digits, never null
     * @see #withHexFontFamily(String)
     */
    public String getHexFontFamily() {
        return hexFontFamily;
    }

    /**
     * @return true if the hex and ASCII tracks draw their digits, the default
     * @see #withHexText(boolean)
     */
    public boolean isHexText() {
        return hexText;
    }

    /**
     * Sets whether the hex and ASCII tracks draw their digits. Without text
     * they only draw the cell colors and the grid, e.g. for a user interface
     * that draws the text itself at the resolution of the screen; see
     * {@link VisualizerColors#textRgbFor(int)} for the text color.
     *
     * @param drawText true to draw the digits
     * @return a style whose hex and ASCII tracks draw or omit the digits
     */
    public RenderStyle withHexText(boolean drawText) {
        return new RenderStyle(byteplotMode, entropyMode, cellRule, layering, paintedTypes, additionalGap,
                pixelated, minimumRegionLength, sampleStep, legacyEntropyWindow, background, hatchColor,
                hatchPending, hexBackground, hexFontFamily, drawText);
    }

    /**
     * Sets the font family of the hex and ASCII digits. Families that are not
     * installed would be replaced by a proportional font, so they give the
     * default family instead, see {@link #defaultHexFontFamily()}.
     *
     * @param family an installed font family, null or blank for the default
     * @return a style whose hex and ASCII tracks use the font family
     */
    public RenderStyle withHexFontFamily(String family) {
        String installed = family == null ? null : InstalledFonts.BY_LOWER_CASE_NAME.get(
                family.trim().toLowerCase(Locale.ROOT));
        return new RenderStyle(byteplotMode, entropyMode, cellRule, layering, paintedTypes, additionalGap,
                pixelated, minimumRegionLength, sampleStep, legacyEntropyWindow, background, hatchColor,
                hatchPending, hexBackground, installed != null ? installed : defaultHexFontFamily(), hexText);
    }

    /**
     * @param track {@link Track#STRUCTURE}, {@link Track#BYTEPLOT} or {@link Track#ENTROPY}
     * @return a style whose hex and ASCII cells have the colors of the track
     * @throws IllegalArgumentException for {@link Track#HEX} and {@link Track#ASCII}
     * @see #getHexBackground()
     */
    public RenderStyle withHexBackground(Track track) {
        return new RenderStyle(byteplotMode, entropyMode, cellRule, layering, paintedTypes, additionalGap,
                pixelated, minimumRegionLength, sampleStep, legacyEntropyWindow, background, hatchColor,
                hatchPending, track, hexFontFamily, hexText);
    }

    public RenderStyle withByteplotMode(ByteplotMode mode) {
        return new RenderStyle(mode, entropyMode, cellRule, layering, paintedTypes, additionalGap, pixelated,
                minimumRegionLength, sampleStep, legacyEntropyWindow, background, hatchColor, hatchPending,
                hexBackground, hexFontFamily, hexText);
    }

    public RenderStyle withEntropyMode(EntropyMode mode) {
        return new RenderStyle(byteplotMode, mode, cellRule, layering, paintedTypes, additionalGap, pixelated,
                minimumRegionLength, sampleStep, legacyEntropyWindow, background, hatchColor, hatchPending,
                hexBackground, hexFontFamily, hexText);
    }

    public RenderStyle withCellRule(CellRule rule) {
        return new RenderStyle(byteplotMode, entropyMode, rule, layering, paintedTypes, additionalGap, pixelated,
                minimumRegionLength, sampleStep, legacyEntropyWindow, background, hatchColor, hatchPending,
                hexBackground, hexFontFamily, hexText);
    }

    public RenderStyle withLayering(Layering newLayering) {
        return new RenderStyle(byteplotMode, entropyMode, cellRule, newLayering, paintedTypes, additionalGap,
                pixelated, minimumRegionLength, sampleStep, legacyEntropyWindow, background, hatchColor,
                hatchPending, hexBackground, hexFontFamily, hexText);
    }

    public RenderStyle withPaintedTypes(Set<RegionType> types) {
        return new RenderStyle(byteplotMode, entropyMode, cellRule, layering, types, additionalGap, pixelated,
                minimumRegionLength, sampleStep, legacyEntropyWindow, background, hatchColor, hatchPending,
                hexBackground, hexFontFamily, hexText);
    }

    /**
     * @param type a region type
     * @param painted true to draw regions of the type
     * @return a style that draws or skips the type, e.g. to toggle markers
     */
    public RenderStyle withPainted(RegionType type, boolean painted) {
        Set<RegionType> types = paintedTypes.isEmpty() ? EnumSet.noneOf(RegionType.class) : EnumSet.copyOf(paintedTypes);
        if (painted) types.add(type);
        else types.remove(type);
        return withPaintedTypes(types);
    }

    public RenderStyle withAdditionalGap(int gap) {
        return new RenderStyle(byteplotMode, entropyMode, cellRule, layering, paintedTypes, gap, pixelated,
                minimumRegionLength, sampleStep, legacyEntropyWindow, background, hatchColor, hatchPending,
                hexBackground, hexFontFamily, hexText);
    }

    public RenderStyle withPixelated(boolean newPixelated) {
        return new RenderStyle(byteplotMode, entropyMode, cellRule, layering, paintedTypes, additionalGap,
                newPixelated, minimumRegionLength, sampleStep, legacyEntropyWindow, background, hatchColor,
                hatchPending, hexBackground, hexFontFamily, hexText);
    }

    public RenderStyle withMinimumRegionLength(double length) {
        return new RenderStyle(byteplotMode, entropyMode, cellRule, layering, paintedTypes, additionalGap,
                pixelated, length, sampleStep, legacyEntropyWindow, background, hatchColor, hatchPending,
                hexBackground, hexFontFamily, hexText);
    }

    public RenderStyle withSampleStep(long step) {
        return new RenderStyle(byteplotMode, entropyMode, cellRule, layering, paintedTypes, additionalGap,
                pixelated, minimumRegionLength, step, legacyEntropyWindow, background, hatchColor, hatchPending,
                hexBackground, hexFontFamily, hexText);
    }

    public RenderStyle withLegacyEntropyWindow(int window) {
        return new RenderStyle(byteplotMode, entropyMode, cellRule, layering, paintedTypes, additionalGap,
                pixelated, minimumRegionLength, sampleStep, window, background, hatchColor, hatchPending,
                hexBackground, hexFontFamily, hexText);
    }

    public RenderStyle withBackground(int argb) {
        return new RenderStyle(byteplotMode, entropyMode, cellRule, layering, paintedTypes, additionalGap,
                pixelated, minimumRegionLength, sampleStep, legacyEntropyWindow, argb, hatchColor, hatchPending,
                hexBackground, hexFontFamily, hexText);
    }

    public RenderStyle withHatchPending(boolean hatch, int color) {
        return new RenderStyle(byteplotMode, entropyMode, cellRule, layering, paintedTypes, additionalGap,
                pixelated, minimumRegionLength, sampleStep, legacyEntropyWindow, background, color, hatch,
                hexBackground, hexFontFamily, hexText);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RenderStyle)) return false;
        RenderStyle that = (RenderStyle) o;
        return additionalGap == that.additionalGap && pixelated == that.pixelated
                && Double.compare(minimumRegionLength, that.minimumRegionLength) == 0
                && sampleStep == that.sampleStep && legacyEntropyWindow == that.legacyEntropyWindow
                && background == that.background && hatchColor == that.hatchColor
                && hatchPending == that.hatchPending && byteplotMode == that.byteplotMode
                && entropyMode == that.entropyMode && cellRule == that.cellRule && layering == that.layering
                && hexBackground == that.hexBackground && hexFontFamily.equals(that.hexFontFamily)
                && hexText == that.hexText
                && paintedTypes.equals(that.paintedTypes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(byteplotMode, entropyMode, cellRule, layering, paintedTypes, additionalGap, pixelated,
                minimumRegionLength, sampleStep, legacyEntropyWindow, background, hatchColor, hatchPending,
                hexBackground, hexFontFamily, hexText);
    }

    @Override
    public String toString() {
        return "RenderStyle[" + byteplotMode + ", " + entropyMode + ", " + cellRule + ", " + layering + ", gap="
                + additionalGap + ", pixelated=" + pixelated + ", hex background=" + hexBackground + ", hex font="
                + hexFontFamily + ", hex text=" + hexText + "]";
    }
}
