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
 * How detailed a {@link StructureMap} is.
 *
 * @author Karsten Philipp Boris Hahn
 */
public enum Detail {
    /**
     * headers, sections, special sections per DLL, block or resource, .NET
     * streams, declared data directories, overlay and markers
     */
    COARSE,
    /**
     * everything of {@link #COARSE} plus header fields, import tables, export
     * tables, the resource directory tree and .NET metadata tables
     */
    FINE
}
