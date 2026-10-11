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
package io.github.struppigel.tools.visualizer.engine;

import io.github.struppigel.tools.layout.StructureMap;
import io.github.struppigel.tools.visualizer.render.RegionColorScheme;

import java.util.Objects;

/**
 * Everything the renderers need to draw one file: its structure map, byte
 * statistics, bytes and region colors.
 * <p>
 * Instances are immutable; the statistics may still be computed while the
 * visualization is rendered. Renderers never touch the PEData, so a
 * visualization can be rendered by several threads at once.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class FileVisualization {

    private final StructureMap structureMap;
    private final ByteStatistics statistics;
    private final ByteSource source;
    private final RegionColorScheme colorScheme;

    /**
     * Creates a visualization.
     *
     * @param structureMap the structure map, {@link StructureMap#empty(long)} for files that are no PE files
     * @param statistics the byte statistics, computed or not
     * @param source the bytes of the file
     * @param colorScheme the colors of the regions of the structure map
     * @throws IllegalArgumentException if the parts belong to files of different lengths
     */
    public FileVisualization(StructureMap structureMap, ByteStatistics statistics, ByteSource source,
                             RegionColorScheme colorScheme) {
        this.structureMap = Objects.requireNonNull(structureMap);
        this.statistics = Objects.requireNonNull(statistics);
        this.source = Objects.requireNonNull(source);
        this.colorScheme = Objects.requireNonNull(colorScheme);
        long length = source.length();
        if (structureMap.getFileLength() != length || statistics.getLength() != length) {
            throw new IllegalArgumentException("file lengths differ: structure map " + structureMap.getFileLength()
                    + ", statistics " + statistics.getLength() + ", bytes " + length);
        }
    }

    /**
     * @return the structure map
     */
    public StructureMap getStructureMap() {
        return structureMap;
    }

    /**
     * @return the byte statistics
     */
    public ByteStatistics getStatistics() {
        return statistics;
    }

    /**
     * @return the bytes of the file
     */
    public ByteSource getSource() {
        return source;
    }

    /**
     * @return the colors of the regions
     */
    public RegionColorScheme getColorScheme() {
        return colorScheme;
    }

    /**
     * @return the length of the file
     */
    public long getFileLength() {
        return source.length();
    }
}
