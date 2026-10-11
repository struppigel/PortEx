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

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.tools.layout.StructureMap;
import io.github.struppigel.tools.visualizer.engine.ByteStatistics;
import io.github.struppigel.tools.visualizer.engine.CachedByteSource;
import io.github.struppigel.tools.visualizer.engine.FileVisualization;
import io.github.struppigel.tools.visualizer.engine.ProgressListener;
import io.github.struppigel.tools.visualizer.engine.Viewport;

import java.io.File;
import java.io.IOException;

/** helpers for renderer tests */
final class RenderTestSupport {

    private RenderTestSupport() {
    }

    static File sample(String name) {
        return new File(TestreportsReader.RESOURCE_DIR + TestreportsReader.TEST_FILE_DIR + "/" + name);
    }

    /** a visualization of a sample with computed statistics; the byte source is never closed */
    static FileVisualization visualization(String name, boolean computeStatistics) throws IOException {
        File file = sample(name);
        PEData data = PELoader.loadPE(file);
        StructureMap map = StructureMap.of(data);
        ByteStatistics stats = new ByteStatistics(file);
        if (computeStatistics) {
            stats.compute(ProgressListener.NONE);
        }
        return new FileVisualization(map, stats, new CachedByteSource(file), RegionColorScheme.of(map));
    }

    static int[] render(Track track, FileVisualization vis, Viewport viewport, int cellWidth, RenderStyle style) {
        int width = viewport.getMapping().getColumns() * cellWidth;
        int[] argb = new int[width * viewport.getRowCount() * viewport.getCellHeight()];
        track.renderer().render(vis, viewport, cellWidth, style, argb, width);
        return argb;
    }

    /** the pixel in the middle of the cell of an offset */
    static int pixelAt(int[] argb, Viewport viewport, int cellWidth, long offset) {
        java.awt.Point p = viewport.pixelOf(offset, cellWidth);
        int width = viewport.getMapping().getColumns() * cellWidth;
        return argb[(p.y + viewport.getCellHeight() / 2) * width + p.x + cellWidth / 2];
    }
}
