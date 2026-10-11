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

import io.github.struppigel.tools.visualizer.engine.ByteSource;
import io.github.struppigel.tools.visualizer.engine.FileVisualization;
import io.github.struppigel.tools.visualizer.engine.ViewMapping;
import io.github.struppigel.tools.visualizer.engine.Viewport;

import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Draws byte values as hex digits or characters on the colors of another
 * track.
 * <p>
 * The cell background is the color of the cell in the track of
 * {@link RenderStyle#getHexBackground()}: the structure color by default,
 * lightened if it is dark, or the exact byte plot or entropy color. The text
 * is black or white, whichever has the higher WCAG contrast, see
 * {@link VisualizerColors#textRgbFor(int)}. With
 * {@link RenderStyle#withHexText(boolean)} false, only the cells and the grid
 * are drawn, e.g. for a user interface that draws the text itself. The glyphs
 * use the font family
 * of {@link RenderStyle#getHexFontFamily()} at the largest size that fits the
 * cell and are pre-rendered once per family and cell size. Meant for one byte
 * per cell; cells with more bytes show their first byte.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class HexRenderer implements TrackRenderer {

    static final HexRenderer HEX = new HexRenderer(false);
    static final HexRenderer ASCII = new HexRenderer(true);

    /** the smallest cell that gets text */
    private static final int MIN_TEXT_WIDTH = 6;
    private static final int MIN_TEXT_HEIGHT = 7;
    /** glyph atlases by font family, cell size and hex or ASCII */
    private static final ConcurrentHashMap<String, int[][]> ATLASES = new ConcurrentHashMap<>();

    private final boolean ascii;

    private HexRenderer(boolean ascii) {
        this.ascii = ascii;
    }

    @Override
    public void render(FileVisualization vis, Viewport viewport, int cellWidth, RenderStyle style, int[] argb,
                       int scanline) {
        Track backgroundTrack = style.getHexBackground();
        TrackRenderer.of(backgroundTrack).render(vis, viewport, cellWidth, style, argb, scanline);
        // byte plot and entropy colors stay exact, so that they match their tracks and the legend
        boolean lightenDark = backgroundTrack == Track.STRUCTURE;
        int width = Cells.width(viewport, cellWidth);
        int height = Cells.height(viewport);
        ViewMapping mapping = viewport.getMapping();
        ByteSource source = vis.getSource();
        int columns = mapping.getColumns();
        int cellHeight = viewport.getCellHeight();
        long bytesPerCell = mapping.getBytesPerCell();
        long fileLength = mapping.getFileLength();
        boolean textFits = cellWidth >= MIN_TEXT_WIDTH && cellHeight >= MIN_TEXT_HEIGHT;
        int[][] atlas = textFits && style.isHexText() ? atlas(style.getHexFontFamily(), cellWidth, cellHeight)
                : null;
        // leave a one pixel grid if the cells are large enough for text, with or without the text
        int inner = textFits ? 1 : 0;

        for (int r = 0; r < viewport.getRowCount(); r++) {
            long rowStart = mapping.getBaseOffset() + (viewport.getFirstRow() + r) * mapping.getBytesPerRow();
            if (rowStart >= fileLength) {
                break;
            }
            int y = r * cellHeight;
            for (int column = 0; column < columns; column++) {
                long offset = rowStart + column * bytesPerCell;
                if (offset >= fileLength) {
                    break;
                }
                int x = column * cellWidth;
                int sampled = argb[(y + cellHeight / 2) * scanline + x + cellWidth / 2];
                int background = lightenDark && VisualizerColors.luminance(sampled) < 0.35 ? lighten(sampled) : sampled;
                Cells.fill(argb, scanline, width, height, x, y, cellWidth - inner, cellHeight - inner, background);
                if (atlas != null) {
                    int value = source.byteAt(offset);
                    int text = VisualizerColors.textRgbFor(background);
                    drawGlyph(argb, scanline, x, y, cellWidth, cellHeight, atlas[glyphIndex(value)], background, text);
                }
            }
        }
    }

    private int glyphIndex(int value) {
        if (!ascii) {
            return value;
        }
        return value >= 33 && value <= 126 ? value : '.';
    }

    private static int lighten(int rgb) {
        int r = (rgb >> 16) & 0xFF;
        int g = (rgb >> 8) & 0xFF;
        int b = rgb & 0xFF;
        r = r + (255 - r) * 2 / 5;
        g = g + (255 - g) * 2 / 5;
        b = b + (255 - b) * 2 / 5;
        return 0xFF000000 | (r << 16) | (g << 8) | b;
    }

    private static void drawGlyph(int[] argb, int scanline, int x, int y, int cellWidth, int cellHeight, int[] mask,
                                  int background, int text) {
        int br = (background >> 16) & 0xFF;
        int bg = (background >> 8) & 0xFF;
        int bb = background & 0xFF;
        int tr = (text >> 16) & 0xFF;
        int tg = (text >> 8) & 0xFF;
        int tb = text & 0xFF;
        for (int py = 0; py < cellHeight; py++) {
            int row = (y + py) * scanline + x;
            for (int px = 0; px < cellWidth; px++) {
                int alpha = mask[py * cellWidth + px];
                if (alpha == 0) {
                    continue;
                }
                int r = (tr * alpha + br * (255 - alpha)) / 255;
                int g = (tg * alpha + bg * (255 - alpha)) / 255;
                int b = (tb * alpha + bb * (255 - alpha)) / 255;
                argb[row + px] = 0xFF000000 | (r << 16) | (g << 8) | b;
            }
        }
    }

    /** alpha masks of the 256 glyphs for a font family and cell size */
    private int[][] atlas(String family, int cellWidth, int cellHeight) {
        String key = family + '|' + cellWidth + 'x' + cellHeight + '|' + (ascii ? "ascii" : "hex");
        int[][] atlas = ATLASES.get(key);
        if (atlas == null) {
            atlas = createAtlas(family, cellWidth, cellHeight);
            int[][] previous = ATLASES.putIfAbsent(key, atlas);
            if (previous != null) {
                atlas = previous;
            }
        }
        return atlas;
    }

    private int[][] createAtlas(String family, int cellWidth, int cellHeight) {
        String sample = ascii ? "W" : "WW";
        int size = Math.max(6, cellHeight - 2);
        Font font;
        FontMetrics metrics;
        BufferedImage image = new BufferedImage(cellWidth, cellHeight, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        do {
            font = new Font(family, Font.PLAIN, size);
            metrics = g.getFontMetrics(font);
            size--;
        } while (size > 5 && (metrics.stringWidth(sample) > cellWidth - 2 || metrics.getAscent() > cellHeight - 1));
        g.dispose();
        int[][] atlas = new int[256][];
        for (int value = 0; value < 256; value++) {
            String glyph = ascii ? String.valueOf((char) value) : String.format("%02X", value);
            BufferedImage glyphImage = new BufferedImage(cellWidth, cellHeight, BufferedImage.TYPE_INT_ARGB);
            Graphics2D gg = glyphImage.createGraphics();
            gg.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            gg.setFont(font);
            gg.setColor(java.awt.Color.WHITE);
            int textWidth = metrics.stringWidth(glyph);
            int textX = (cellWidth - 1 - textWidth) / 2;
            int textY = (cellHeight - 1 - metrics.getHeight()) / 2 + metrics.getAscent();
            if (ascii && (value < 33 || value > 126)) {
                glyph = ".";
            }
            gg.drawString(glyph, textX, textY);
            gg.dispose();
            int[] pixels = glyphImage.getRGB(0, 0, cellWidth, cellHeight, null, 0, cellWidth);
            int[] mask = new int[pixels.length];
            for (int i = 0; i < pixels.length; i++) {
                mask[i] = (pixels[i] >>> 24) & 0xFF;
            }
            atlas[value] = mask;
        }
        return atlas;
    }
}
