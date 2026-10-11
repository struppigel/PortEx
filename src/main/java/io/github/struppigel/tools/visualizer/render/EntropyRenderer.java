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

import io.github.struppigel.tools.ShannonEntropy;
import io.github.struppigel.tools.visualizer.engine.ByteSource;
import io.github.struppigel.tools.visualizer.engine.ByteStatistics;
import io.github.struppigel.tools.visualizer.engine.ByteStats;
import io.github.struppigel.tools.visualizer.engine.FileVisualization;
import io.github.struppigel.tools.visualizer.engine.LocalEntropy;
import io.github.struppigel.tools.visualizer.engine.ViewMapping;
import io.github.struppigel.tools.visualizer.engine.Viewport;

/**
 * Draws the local entropy. The brightness of the entropy color is the
 * entropy.
 * <p>
 * Cells of at least one statistics block use the precomputed
 * {@link ByteStatistics}; cells whose statistics are not computed yet are
 * hatched. Smaller cells are computed from the bytes with
 * {@link LocalEntropy}. {@link RenderStyle.EntropyMode#LEGACY_WINDOW} computes
 * the entropy of one window per cell like the classic visualizer.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class EntropyRenderer implements TrackRenderer {

    static final EntropyRenderer INSTANCE = new EntropyRenderer();

    private EntropyRenderer() {
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
        RenderStyle.EntropyMode mode = style.getEntropyMode();
        boolean useStatistics = mode != RenderStyle.EntropyMode.LEGACY_WINDOW && bytesPerCell >= stats.getBlockSize();
        long done = stats.getComputedLength();
        long rowPixelOffset = viewport.getFirstRow() * cellHeight;
        ByteStats cellStats = new ByteStats();
        double[] mean = new double[columns];
        double[] max = new double[columns];
        int window = style.getLegacyEntropyWindow();
        int halfWindow = (int) Math.round(window / 2.0);
        byte[] windowBytes = new byte[window];

        for (int r = 0; r < viewport.getRowCount(); r++) {
            long row = viewport.getFirstRow() + r;
            long rowStart = mapping.getBaseOffset() + row * mapping.getBytesPerRow();
            if (rowStart >= fileLength) {
                break;
            }
            int y = r * cellHeight;
            if (!useStatistics && mode != RenderStyle.EntropyMode.LEGACY_WINDOW) {
                LocalEntropy.compute(source, rowStart, (int) bytesPerCell, columns, mean, max);
            }
            for (int column = 0; column < columns; column++) {
                long cellStart = rowStart + column * bytesPerCell;
                if (cellStart >= fileLength) {
                    break;
                }
                long cellEnd = Math.min(fileLength, cellStart + bytesPerCell);
                int x = column * cellWidth;
                double entropy;
                if (mode == RenderStyle.EntropyMode.LEGACY_WINDOW) {
                    long sample = Cells.sampleOffset(cellStart, bytesPerCell, style.getSampleStep());
                    if (sample >= fileLength) {
                        continue;
                    }
                    long windowStart = Math.max(0, sample - halfWindow);
                    int n = (int) Math.min(fileLength - windowStart, window);
                    byte[] bytes = n == window ? windowBytes : new byte[n];
                    int read = source.read(windowStart, bytes, 0, n);
                    if (read < n) {
                        bytes = java.util.Arrays.copyOf(bytes, read);
                    }
                    entropy = ShannonEntropy.entropy(bytes);
                } else if (useStatistics) {
                    if (cellEnd > done) {
                        if (style.isHatchPending()) {
                            Cells.hatch(argb, scanline, width, height, x, y, cellWidth, cellHeight, rowPixelOffset,
                                    style.getBackground(), style.getHatchColor());
                        }
                        continue;
                    }
                    stats.aggregate(cellStart, cellEnd, cellStats);
                    entropy = mode == RenderStyle.EntropyMode.MAX ? cellStats.getMaxEntropy()
                            : cellStats.getMeanEntropy();
                } else {
                    entropy = mode == RenderStyle.EntropyMode.MAX ? max[column] : mean[column];
                    if (Double.isNaN(entropy)) {
                        continue;
                    }
                }
                Cells.fillCell(argb, scanline, width, height, x, y, cellWidth, cellHeight, 0, pixelated,
                        scheme.entropyRgb(entropy));
            }
        }
    }
}
