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
import io.github.struppigel.tools.layout.IntervalVisitor;
import io.github.struppigel.tools.layout.PaintMode;
import io.github.struppigel.tools.layout.RegionType;
import io.github.struppigel.tools.visualizer.engine.FileVisualization;
import io.github.struppigel.tools.visualizer.engine.ViewMapping;
import io.github.struppigel.tools.visualizer.engine.Viewport;

import java.util.Arrays;
import java.util.Comparator;

/**
 * Draws the structures of the structure map.
 * <p>
 * With {@link RenderStyle.Layering#SPECIFICITY}, filled regions are drawn
 * from the least to the most specific one, so the innermost structure wins.
 * Then inset regions and markers are drawn on top, inset by the additional
 * gap, with at least one cell each, so that small structures like the PE
 * signature or the entry point are visible at every zoom level. The inset is
 * reduced for small cells, so that at least one pixel is drawn. Markers that
 * cover more than 16 cells, e.g. an anomaly of the whole overlay, are drawn
 * as a one pixel outline of their cells, so that the structures below them
 * stay visible. Regions whose
 * type has {@link PaintMode#NONE} are never drawn.
 * <p>
 * With {@link RenderStyle.Layering#LEGACY_ORDER}, regions are drawn in the
 * fixed order of the classic visualizer.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class StructureRenderer implements TrackRenderer {

    static final StructureRenderer INSTANCE = new StructureRenderer();

    /** markers that cover more cells are outlined instead of filled */
    static final int MAX_FILLED_MARKER_CELLS = 16;

    private StructureRenderer() {
    }

    /** regions that overlap a tile in visiting order */
    private static final class Intervals implements IntervalVisitor {
        final RenderStyle style;
        FileRegion[] regions = new FileRegion[64];
        long[] starts = new long[64];
        long[] ends = new long[64];
        int size;

        Intervals(RenderStyle style) {
            this.style = style;
        }

        @Override
        public void visit(FileRegion region, long start, long end) {
            if (!style.paints(region.getType())) {
                return;
            }
            if (size == regions.length) {
                regions = Arrays.copyOf(regions, size * 2);
                starts = Arrays.copyOf(starts, size * 2);
                ends = Arrays.copyOf(ends, size * 2);
            }
            regions[size] = region;
            starts[size] = start;
            ends[size] = end;
            size++;
        }
    }

    @Override
    public void render(FileVisualization vis, Viewport viewport, int cellWidth, RenderStyle style, int[] argb,
                       int scanline) {
        int width = Cells.width(viewport, cellWidth);
        int height = Cells.height(viewport);
        Cells.fill(argb, scanline, width, height, 0, 0, width, height, style.getBackground());
        ViewMapping mapping = viewport.getMapping();
        long from = Cells.firstOffset(viewport);
        long to = Math.min(mapping.getFileLength(), from + viewport.getRowCount() * mapping.getBytesPerRow());
        if (from >= to) {
            return;
        }
        final Intervals intervals = new Intervals(style);
        vis.getStructureMap().forEachInterval(from, to, intervals);
        Painter painter = new Painter(vis.getColorScheme(), viewport, cellWidth, style, argb, scanline, width, height);
        if (style.getLayering() == RenderStyle.Layering.LEGACY_ORDER) {
            Integer[] order = new Integer[intervals.size];
            for (int i = 0; i < order.length; i++) {
                order[i] = i;
            }
            Arrays.sort(order, new Comparator<Integer>() {
                @Override
                public int compare(Integer a, Integer b) {
                    FileRegion ra = intervals.regions[a];
                    FileRegion rb = intervals.regions[b];
                    int c = Integer.compare(legacyLayer(ra.getType()), legacyLayer(rb.getType()));
                    if (c != 0) return c;
                    c = Integer.compare(ra.getId(), rb.getId());
                    return c != 0 ? c : Long.compare(intervals.starts[a], intervals.starts[b]);
                }
            });
            for (int i : order) {
                FileRegion region = intervals.regions[i];
                int gap = region.getType().getPaintMode() == PaintMode.FILL ? 0 : style.getAdditionalGap();
                painter.paint(region, intervals.starts[i], intervals.ends[i], gap, false, false);
            }
        } else {
            // small cells get a smaller inset, so that inset regions and markers stay visible
            int smallest = Math.min(cellWidth, viewport.getCellHeight());
            int maxGap = style.isPixelated() ? (smallest - 1) / 2 - 1 : smallest - 1;
            int insetGap = Math.max(0, Math.min(style.getAdditionalGap(), maxGap));
            PaintMode[] passes = {PaintMode.FILL, PaintMode.INSET, PaintMode.MARKER};
            for (PaintMode pass : passes) {
                boolean filled = pass == PaintMode.FILL;
                int gap = filled ? 0 : insetGap;
                boolean marker = pass == PaintMode.MARKER;
                for (int i = 0; i < intervals.size; i++) {
                    FileRegion region = intervals.regions[i];
                    if (region.getType().getPaintMode() == pass) {
                        painter.paint(region, intervals.starts[i], intervals.ends[i], gap, !filled, marker);
                    }
                }
            }
        }
    }

    /** the drawing order of the classic visualizer */
    static int legacyLayer(RegionType type) {
        switch (type) {
            case SECTION: return 0;
            case OVERLAY: return 1;
            case MSDOS_HEADER: return 2;
            case RICH_HEADER: return 3;
            case CLR_HEADER:
            case METADATA_ROOT: return 4;
            case CLR_STREAM: return 5;
            case OPTIONAL_HEADER: return 6;
            case COFF_FILE_HEADER: return 7;
            case SECTION_TABLE: return 8;
            case RESOURCE_DIRECTORY: return 9;
            case IMPORT_SECTION: return 10;
            case DELAY_IMPORT_SECTION: return 11;
            case EXPORT_SECTION: return 12;
            case RELOCATION: return 13;
            case DEBUG_DIRECTORY:
            case CODEVIEW: return 14;
            case ENTRY_POINT: return 15;
            case CUSTOM: return 16;
            case RESOURCE: return 17;
            default: return 18;
        }
    }

    /** maps file ranges to the cells of one tile and fills them */
    private static final class Painter {
        final RegionColorScheme scheme;
        final RenderStyle style;
        final int[] argb;
        final int scanline;
        final int width;
        final int height;
        final int cellWidth;
        final int cellHeight;
        final int columns;
        final long base;
        final long bytesPerCell;
        final long fileLength;
        final long tileFirstCell;
        final long tileCells;
        final long lastCell;
        final long lastCellMid;
        final boolean lastCellPartial;

        Painter(RegionColorScheme scheme, Viewport viewport, int cellWidth, RenderStyle style, int[] argb,
                int scanline, int width, int height) {
            ViewMapping mapping = viewport.getMapping();
            this.scheme = scheme;
            this.style = style;
            this.argb = argb;
            this.scanline = scanline;
            this.width = width;
            this.height = height;
            this.cellWidth = cellWidth;
            this.cellHeight = viewport.getCellHeight();
            this.columns = mapping.getColumns();
            this.base = mapping.getBaseOffset();
            this.bytesPerCell = mapping.getBytesPerCell();
            this.fileLength = mapping.getFileLength();
            this.tileFirstCell = viewport.getFirstRow() * columns;
            this.tileCells = (long) viewport.getRowCount() * columns;
            this.lastCell = (fileLength - 1 - base) / bytesPerCell;
            long lastStart = base + lastCell * bytesPerCell;
            this.lastCellPartial = lastStart + bytesPerCell > fileLength;
            this.lastCellMid = lastStart + (fileLength - lastStart) / 2;
        }

        void paint(FileRegion region, long start, long end, int gap, boolean atLeastOneCell,
                   boolean outlineLarge) {
            long first;
            long endCell;
            if (style.getCellRule() == RenderStyle.CellRule.FLOOR) {
                long length = end - start;
                double minimum = style.getMinimumRegionLength();
                if (minimum > 0 && region.getType() != RegionType.SECTION) {
                    double m = Math.max(1, minimum);
                    if (length < m) {
                        length = Math.round(m);
                    }
                }
                first = Math.floorDiv(start - base, bytesPerCell);
                endCell = Math.floorDiv(start + length - base, bytesPerCell);
            } else {
                // cells whose middle byte lies in [start, end)
                long half = bytesPerCell / 2;
                first = ceilDiv(start - base - half, bytesPerCell);
                endCell = ceilDiv(end - base - half, bytesPerCell);
                if (lastCellPartial) {
                    // the middle of the last cell is the middle of its bytes
                    boolean covers = start <= lastCellMid && lastCellMid < end;
                    boolean included = first <= lastCell && lastCell < endCell;
                    if (covers && !included) {
                        first = Math.min(first, lastCell);
                        endCell = lastCell + 1;
                    } else if (!covers && included) {
                        endCell = lastCell;
                    }
                }
            }
            if (atLeastOneCell && endCell <= first) {
                first = Math.floorDiv(start - base, bytesPerCell);
                endCell = first + 1;
            }
            long from = Math.max(first, tileFirstCell);
            long to = Math.min(endCell, tileFirstCell + tileCells);
            if (from >= to) {
                return;
            }
            int color = scheme.rgbOf(region);
            boolean pixelated = style.isPixelated();
            boolean outline = outlineLarge && endCell - first > MAX_FILLED_MARKER_CELLS;
            for (long cell = from; cell < to; cell++) {
                long local = cell - tileFirstCell;
                int x = (int) (local % columns) * cellWidth;
                int y = (int) (local / columns) * cellHeight;
                if (outline) {
                    outlineCell(cell, first, endCell, x, y, color);
                } else {
                    Cells.fillCell(argb, scanline, width, height, x, y, cellWidth, cellHeight, gap, pixelated,
                            color);
                }
            }
        }

        /** draws the edges of a cell that border cells outside of [first, endCell) */
        private void outlineCell(long cell, long first, long endCell, int x, int y, int color) {
            int column = (int) (cell % columns);
            if (column == 0 || cell - 1 < first) {
                Cells.fill(argb, scanline, width, height, x, y, 1, cellHeight, color);
            }
            if (column == columns - 1 || cell + 1 >= endCell) {
                Cells.fill(argb, scanline, width, height, x + cellWidth - 1, y, 1, cellHeight, color);
            }
            if (cell - columns < first) {
                Cells.fill(argb, scanline, width, height, x, y, cellWidth, 1, color);
            }
            if (cell + columns >= endCell) {
                Cells.fill(argb, scanline, width, height, x, y + cellHeight - 1, cellWidth, 1, color);
            }
        }

        private static long ceilDiv(long a, long b) {
            return -Math.floorDiv(-a, b);
        }
    }
}
