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

import io.github.struppigel.tools.visualizer.engine.ViewMapping;
import io.github.struppigel.tools.visualizer.engine.Viewport;

/**
 * Drawing helpers shared by the renderers.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class Cells {

    private Cells() {
    }

    /** fills a rectangle, clipped to the drawn area */
    static void fill(int[] argb, int scanline, int width, int height, int x, int y, int w, int h, int color) {
        int x0 = Math.max(0, x);
        int y0 = Math.max(0, y);
        int x1 = Math.min(width, x + w);
        int y1 = Math.min(height, y + h);
        for (int py = y0; py < y1; py++) {
            int row = py * scanline;
            for (int px = x0; px < x1; px++) {
                argb[row + px] = color;
            }
        }
    }

    /**
     * Fills a cell like the classic visualizer: an inset of gap pixels at the
     * top and left; pixelated cells have one more pixel of inset on all sides.
     */
    static void fillCell(int[] argb, int scanline, int width, int height, int x, int y, int cellWidth,
                         int cellHeight, int gap, boolean pixelated, int color) {
        int g = pixelated ? gap + 1 : gap;
        int modifier = pixelated ? 2 : 1;
        fill(argb, scanline, width, height, x + g, y + g, cellWidth - g * modifier, cellHeight - g * modifier,
                color);
    }

    /** fills a cell with a diagonal hatch pattern that continues across tiles */
    static void hatch(int[] argb, int scanline, int width, int height, int x, int y, int cellWidth, int cellHeight,
                      long rowPixelOffset, int background, int hatchColor) {
        int x1 = Math.min(width, x + cellWidth);
        int y1 = Math.min(height, y + cellHeight);
        for (int py = Math.max(0, y); py < y1; py++) {
            int row = py * scanline;
            long absoluteY = rowPixelOffset + py;
            for (int px = Math.max(0, x); px < x1; px++) {
                argb[row + px] = ((px + absoluteY) & 7) < 2 ? hatchColor : background;
            }
        }
    }

    /** width of the drawn area */
    static int width(Viewport viewport, int cellWidth) {
        return viewport.getMapping().getColumns() * cellWidth;
    }

    /** height of the drawn area */
    static int height(Viewport viewport) {
        return viewport.getRowCount() * viewport.getCellHeight();
    }

    /** file offset of the first cell of the viewport, may be beyond the file */
    static long firstOffset(Viewport viewport) {
        ViewMapping m = viewport.getMapping();
        return m.getBaseOffset() + viewport.getFirstRow() * m.getBytesPerRow();
    }

    /**
     * Returns the sampled offset of a cell: the cell start, or with a sample
     * step the last multiple of the step before the cell end, like the loops
     * of the classic visualizer.
     */
    static long sampleOffset(long cellStart, long bytesPerCell, long sampleStep) {
        if (sampleStep <= 0) {
            return cellStart;
        }
        long cellEnd = cellStart + bytesPerCell;
        return ((cellEnd - 1) / sampleStep) * sampleStep;
    }
}
