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
import io.github.struppigel.tools.visualizer.engine.FileVisualization;
import io.github.struppigel.tools.visualizer.engine.ViewMapping;
import io.github.struppigel.tools.visualizer.engine.Viewport;

import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferInt;
import java.util.Collections;
import java.util.List;

/**
 * Draws images of several tracks side by side with an offset ruler and a
 * legend, e.g. for the command line or to export a view.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class VisualizationRenderer {

    /** width of the offset ruler in pixels */
    public static final int RULER_WIDTH = 90;
    /** gap between tracks in pixels */
    public static final int TRACK_GAP = 4;
    /** minimum width of the legend in pixels; it is wider if its labels need more space */
    public static final int LEGEND_WIDTH = 220;
    /** minimum cell width of the hex track */
    public static final int HEX_CELL_WIDTH = 20;
    /** minimum cell width of the ASCII track */
    public static final int ASCII_CELL_WIDTH = 10;

    private static final int RULER_BACKGROUND = 0xFF202020;

    private VisualizationRenderer() {
    }

    /**
     * Draws all rows of a mapping.
     *
     * @param vis the visualization
     * @param mapping the mapping
     * @param tracks the tracks from left to right
     * @param cellWidth the cell width of byte plot, entropy and structure tracks
     * @param cellHeight the height of a row
     * @param style the render style
     * @return the image
     */
    public static BufferedImage renderComposite(FileVisualization vis, ViewMapping mapping, List<Track> tracks,
                                                int cellWidth, int cellHeight, RenderStyle style) {
        long rows = Math.max(1, mapping.getRowCount());
        if (rows * cellHeight > Integer.MAX_VALUE / 4) {
            throw new IllegalArgumentException("image too high: " + rows + " rows");
        }
        return renderComposite(vis, mapping, 0, (int) rows, tracks, cellWidth, cellHeight, style, true);
    }

    /**
     * Draws a range of rows: an offset ruler, the tracks and optionally a
     * legend. Hex and ASCII tracks get wider cells, see
     * {@link #cellWidthOf(Track, int)}.
     *
     * @param vis the visualization
     * @param mapping the mapping
     * @param firstRow the first row to draw
     * @param rowCount the number of rows to draw
     * @param tracks the tracks from left to right
     * @param cellWidth the cell width of byte plot, entropy and structure tracks
     * @param cellHeight the height of a row
     * @param style the render style
     * @param withLegend true to add a legend at the right
     * @return the image
     */
    public static BufferedImage renderComposite(FileVisualization vis, ViewMapping mapping, long firstRow,
                                                int rowCount, List<Track> tracks, int cellWidth, int cellHeight,
                                                RenderStyle style, boolean withLegend) {
        Viewport viewport = new Viewport(mapping, firstRow, rowCount, cellHeight);
        int height = Math.max(1, rowCount * cellHeight);
        BufferedImage legend = withLegend ? legend(vis, tracks, style, height) : null;
        int width = RULER_WIDTH;
        for (Track track : tracks) {
            width += TRACK_GAP + mapping.getColumns() * cellWidthOf(track, cellWidth);
        }
        if (legend != null) {
            width += TRACK_GAP + Math.max(LEGEND_WIDTH, legend.getWidth());
        }
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        int[] pixels = ((DataBufferInt) image.getRaster().getDataBuffer()).getData();
        drawRuler(image, viewport);
        int x = RULER_WIDTH;
        for (Track track : tracks) {
            x += TRACK_GAP;
            int trackCellWidth = cellWidthOf(track, cellWidth);
            int trackWidth = mapping.getColumns() * trackCellWidth;
            int[] buffer = new int[trackWidth * height];
            track.renderer().render(vis, viewport, trackCellWidth, style, buffer, trackWidth);
            for (int y = 0; y < height; y++) {
                System.arraycopy(buffer, y * trackWidth, pixels, y * width + x, trackWidth);
            }
            x += trackWidth;
        }
        if (legend != null) {
            Graphics2D g = image.createGraphics();
            g.drawImage(legend, x + TRACK_GAP, 0, null);
            g.dispose();
        }
        return image;
    }

    /** a legend of the tracks whose width fits its labels */
    private static BufferedImage legend(FileVisualization vis, List<Track> tracks, RenderStyle style, int height) {
        boolean byteplot = tracks.contains(Track.BYTEPLOT);
        boolean entropy = tracks.contains(Track.ENTROPY);
        boolean structure = tracks.contains(Track.STRUCTURE) || tracks.contains(Track.HEX);
        List<LegendEntry> entries = LegendRenderer.entries(vis.getStructureMap(), vis.getColorScheme(), byteplot,
                entropy, structure ? style.getPaintedTypes() : Collections.<RegionType>emptySet());
        return LegendRenderer.renderFitted(entries, height);
    }

    /**
     * @param track a track
     * @param cellWidth the cell width of byte plot, entropy and structure tracks
     * @return the cell width of the track
     */
    public static int cellWidthOf(Track track, int cellWidth) {
        switch (track) {
            case HEX:
                return Math.max(cellWidth, HEX_CELL_WIDTH);
            case ASCII:
                return Math.max(cellWidth, ASCII_CELL_WIDTH);
            default:
                return cellWidth;
        }
    }

    private static void drawRuler(BufferedImage image, Viewport viewport) {
        Graphics2D g = image.createGraphics();
        try {
            g.setColor(new Color(RULER_BACKGROUND, true));
            g.fillRect(0, 0, RULER_WIDTH, image.getHeight());
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            g.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            g.setColor(Color.lightGray);
            int cellHeight = viewport.getCellHeight();
            int every = Math.max(1, (14 + cellHeight - 1) / cellHeight);
            ViewMapping mapping = viewport.getMapping();
            for (int r = 0; r < viewport.getRowCount(); r++) {
                long row = viewport.getFirstRow() + r;
                if (row % every != 0) {
                    continue;
                }
                long offset = mapping.getBaseOffset() + row * mapping.getBytesPerRow();
                if (offset >= mapping.getFileLength()) {
                    break;
                }
                g.drawString(String.format("0x%08X", offset), 4, r * cellHeight + 11);
            }
        } finally {
            g.dispose();
        }
    }
}
