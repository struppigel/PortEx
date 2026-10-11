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
 * Receives the locations of regions, see
 * {@link StructureMap#forEachInterval(long, long, IntervalVisitor)}.
 *
 * @author Karsten Philipp Boris Hahn
 */
public interface IntervalVisitor {

    /**
     * Called once for each location of a region that overlaps the queried range.
     *
     * @param region the region the location belongs to
     * @param start the file offset of the location
     * @param end the exclusive end of the location
     */
    void visit(FileRegion region, long start, long end);
}
