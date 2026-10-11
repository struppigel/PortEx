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
package io.github.struppigel.tools.layout;

/**
 * How a structure renderer draws the regions of a {@link RegionType}.
 *
 * @author Karsten Philipp Boris Hahn
 */
public enum PaintMode {
    /** fills the cells it covers */
    FILL,
    /** drawn inset on top of the filled cells, at least one cell */
    INSET,
    /**
     * drawn inset on top of everything else, at least one cell; markers that
     * cover many cells are outlined instead, so that they do not hide the
     * structures below them
     */
    MARKER,
    /** never drawn, only listed as information */
    NONE
}
