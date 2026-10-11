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

import io.github.struppigel.tools.visualizer.engine.ByteClass;
import io.github.struppigel.tools.visualizer.engine.ByteSource;
import io.github.struppigel.tools.visualizer.engine.ByteStatistics;
import io.github.struppigel.tools.visualizer.engine.ByteStats;
import io.github.struppigel.tools.visualizer.engine.FileVisualization;
import io.github.struppigel.tools.visualizer.engine.ViewMapping;
import io.github.struppigel.tools.visualizer.engine.Viewport;

/**
 * Draws byte values colored by their {@link ByteClass}.
 * <p>
 * A cell that covers several bytes shows, depending on the
 * {@link RenderStyle.ByteplotMode}, its dominant class, the mean color of its
 * bytes or one sampled byte. Within a class the color depends linearly on the
 * byte value, so the color of the mean value of a class is the mean color of
 * its bytes. Cells of at least one statistics block use the precomputed
 * {@link ByteStatistics} and are hatched while those are pending; smaller
 * cells are computed from the bytes.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class ByteplotRenderer implements TrackRenderer {

    static final ByteplotRenderer INSTANCE = new ByteplotRenderer();
    private static final ByteClass[] CLASSES = ByteClass.values();

    private ByteplotRenderer() {
    }

    @Override
    public void render(FileVisualization vis, Viewport viewport, int cellWidth, RenderStyle style, int[] argb,
                       int scanline) {
        int width = Cells.width(viewport, cellWidth);
        int height = Cells.height(viewport);
        Cells.fill(argb, scanline, width, height, 0, 0, width, height, style.getBackground());
        ViewMapping mapping = viewport.getMapping();
        RegionColorScheme scheme = vis.getColorScheme();
        ByteStatistics stats = vis.getStatistics();
        ByteSource source = vis.getSource();
        int columns = mapping.getColumns();
        int cellHeight = viewport.getCellHeight();
        long bytesPerCell = mapping.getBytesPerCell();
        long fileLength = mapping.getFileLength();
        boolean pixelated = style.isPixelated();
        RenderStyle.ByteplotMode mode = style.getByteplotMode();
        boolean useStatistics = mode != RenderStyle.ByteplotMode.FIRST_BYTE && bytesPerCell >= stats.getBlockSize();
        long done = stats.getComputedLength();
        long rowPixelOffset = viewport.getFirstRow() * cellHeight;
        ByteStats cellStats = new ByteStats();
        double[] fraction = new double[CLASSES.length];
        double[] meanValue = new double[CLASSES.length];
        byte[] rowBytes = null;

        for (int r = 0; r < viewport.getRowCount(); r++) {
            long row = viewport.getFirstRow() + r;
            long rowStart = mapping.getBaseOffset() + row * mapping.getBytesPerRow();
            if (rowStart >= fileLength) {
                break;
            }
            int y = r * cellHeight;
            int rowLength = 0;
            if (mode != RenderStyle.ByteplotMode.FIRST_BYTE && !useStatistics) {
                if (rowBytes == null) {
                    rowBytes = new byte[(int) mapping.getBytesPerRow()];
                }
                rowLength = source.read(rowStart, rowBytes, 0, rowBytes.length);
            }
            for (int column = 0; column < columns; column++) {
                long cellStart = rowStart + column * bytesPerCell;
                if (cellStart >= fileLength) {
                    break;
                }
                long cellEnd = Math.min(fileLength, cellStart + bytesPerCell);
                int x = column * cellWidth;
                int color;
                if (mode == RenderStyle.ByteplotMode.FIRST_BYTE) {
                    long sample = Cells.sampleOffset(cellStart, bytesPerCell, style.getSampleStep());
                    if (sample >= fileLength) {
                        continue;
                    }
                    color = scheme.bytePlotRgb(source.byteAt(sample));
                } else {
                    if (useStatistics) {
                        if (cellEnd > done) {
                            if (style.isHatchPending()) {
                                Cells.hatch(argb, scanline, width, height, x, y, cellWidth, cellHeight,
                                        rowPixelOffset, style.getBackground(), style.getHatchColor());
                            }
                            continue;
                        }
                        stats.aggregate(cellStart, cellEnd, cellStats);
                        for (ByteClass c : CLASSES) {
                            fraction[c.ordinal()] = cellStats.getFraction(c);
                            meanValue[c.ordinal()] = cellStats.getMeanValue(c);
                        }
                    } else {
                        int from = (int) (cellStart - rowStart);
                        int to = (int) Math.min(rowLength, cellEnd - rowStart);
                        if (to <= from) {
                            continue;
                        }
                        if (to - from == 1) {
                            // one byte has exactly its byte plot color, as in the legend
                            Cells.fillCell(argb, scanline, width, height, x, y, cellWidth, cellHeight, 0, pixelated,
                                    scheme.bytePlotRgb(rowBytes[from]));
                            continue;
                        }
                        countClasses(rowBytes, from, to, fraction, meanValue);
                    }
                    color = mode == RenderStyle.ByteplotMode.DOMINANT ? dominantColor(scheme, fraction, meanValue)
                            : averageColor(scheme, fraction, meanValue);
                }
                Cells.fillCell(argb, scanline, width, height, x, y, cellWidth, cellHeight, 0, pixelated, color);
            }
        }
    }

    private static void countClasses(byte[] bytes, int from, int to, double[] fraction, double[] meanValue) {
        long[] count = new long[CLASSES.length];
        long[] sum = new long[CLASSES.length];
        for (int i = from; i < to; i++) {
            int b = bytes[i] & 0xFF;
            int c = ByteClass.of(b).ordinal();
            count[c]++;
            sum[c] += b;
        }
        int n = to - from;
        for (int c = 0; c < CLASSES.length; c++) {
            fraction[c] = count[c] / (double) n;
            meanValue[c] = count[c] == 0 ? 0 : sum[c] / (double) count[c];
        }
    }

    private static int dominantColor(RegionColorScheme scheme, double[] fraction, double[] meanValue) {
        int best = 0;
        for (int c = 1; c < CLASSES.length; c++) {
            if (fraction[c] > fraction[best]) {
                best = c;
            }
        }
        return scheme.classRgb(CLASSES[best], meanValue[best]);
    }

    private static int averageColor(RegionColorScheme scheme, double[] fraction, double[] meanValue) {
        double r = 0;
        double g = 0;
        double b = 0;
        double total = 0;
        for (int c = 0; c < CLASSES.length; c++) {
            if (fraction[c] <= 0) {
                continue;
            }
            int rgb = scheme.classRgb(CLASSES[c], meanValue[c]);
            r += fraction[c] * ((rgb >> 16) & 0xFF);
            g += fraction[c] * ((rgb >> 8) & 0xFF);
            b += fraction[c] * (rgb & 0xFF);
            total += fraction[c];
        }
        if (total <= 0) {
            return 0xFF000000;
        }
        return 0xFF000000 | ((int) Math.round(r / total) << 16) | ((int) Math.round(g / total) << 8)
                | (int) Math.round(b / total);
    }
}
