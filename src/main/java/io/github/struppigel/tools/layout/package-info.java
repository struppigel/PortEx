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
/**
 * Maps file offsets of a PE file to the structures found there.
 * <p>
 * A {@link io.github.struppigel.tools.layout.StructureMap} is built once per
 * file with a {@link io.github.struppigel.tools.layout.StructureMapBuilder}. It
 * answers which {@link io.github.struppigel.tools.layout.FileRegion}s cover an
 * offset or a range, e.g. the PE signature, a section, a resource or an import
 * DLL. A built map is immutable and can be shared between threads.
 *
 * @author Karsten Philipp Boris Hahn
 *
 */
package io.github.struppigel.tools.layout;
