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

import io.github.struppigel.tools.visualizer.engine.FileVisualization;
import io.github.struppigel.tools.visualizer.engine.Viewport;

/**
 * Draws one track of a file visualization.
 * <p>
 * A renderer draws the rows of a viewport into an int buffer, e.g. the data
 * buffer of a {@link java.awt.image.BufferedImage} of type
 * {@link java.awt.image.BufferedImage#TYPE_INT_RGB} or TYPE_INT_ARGB. The
 * drawn area is {@code columns * cellWidth} pixels wide and
 * {@code rowCount * cellHeight} pixels high, its top left pixel is
 * {@code argb[0]}. Pixel (x, y) is {@code argb[y * scanline + x]}.
 * <p>
 * Renderers are stateless and thread-safe, so tiles, i.e. ranges of rows, can
 * be rendered in parallel. The output only depends on the arguments and the
 * computed length of the statistics. Renderers never touch the PEData.
 *
 * @author Karsten Philipp Boris Hahn
 */
public interface TrackRenderer {

    /**
     * Draws the rows of the viewport.
     *
     * @param vis the visualization
     * @param viewport the rows to draw
     * @param cellWidth the width of a cell of this track in pixels
     * @param style the render style
     * @param argb the buffer to draw into
     * @param scanline the number of ints per row of pixels in the buffer
     * @throws io.github.struppigel.tools.visualizer.engine.ByteSourceClosedException
     *             if the byte source of the visualization was closed
     */
    void render(FileVisualization vis, Viewport viewport, int cellWidth, RenderStyle style, int[] argb, int scanline);

    /**
     * @param track a track
     * @return the renderer of the track
     */
    static TrackRenderer of(Track track) {
        switch (track) {
            case BYTEPLOT:
                return ByteplotRenderer.INSTANCE;
            case ENTROPY:
                return EntropyRenderer.INSTANCE;
            case STRUCTURE:
                return StructureRenderer.INSTANCE;
            case HEX:
                return HexRenderer.HEX;
            case ASCII:
                return HexRenderer.ASCII;
            default:
                throw new IllegalArgumentException("unknown track " + track);
        }
    }
}
