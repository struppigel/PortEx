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

/**
 * The tracks of a file visualization. All tracks share the rows and columns
 * of one {@link io.github.struppigel.tools.visualizer.engine.ViewMapping}.
 *
 * @author Karsten Philipp Boris Hahn
 */
public enum Track {
    /** byte values colored by class */
    BYTEPLOT,
    /** local entropy */
    ENTROPY,
    /** file structures colored by type */
    STRUCTURE,
    /** hex values on structure colors, for one byte per cell */
    HEX,
    /** printable characters, for one byte per cell */
    ASCII;

    /**
     * @return the renderer of this track
     */
    public TrackRenderer renderer() {
        return TrackRenderer.of(this);
    }
}
