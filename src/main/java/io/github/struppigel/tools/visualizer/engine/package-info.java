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
 * Headless engine for interactive file visualizations.
 * <p>
 * {@link io.github.struppigel.tools.visualizer.engine.ByteStatistics} computes
 * entropy and byte class statistics of a file once and aggregates them for any
 * range. {@link io.github.struppigel.tools.visualizer.engine.CachedByteSource}
 * gives fast random access to the bytes.
 * {@link io.github.struppigel.tools.visualizer.engine.ViewMapping} and
 * {@link io.github.struppigel.tools.visualizer.engine.Viewport} convert between
 * file offsets and cells or pixels.
 * {@link io.github.struppigel.tools.visualizer.engine.FileVisualization}
 * bundles everything the renderers of
 * {@link io.github.struppigel.tools.visualizer.render} need.
 * <p>
 * The classes are immutable or thread-safe. They do not cache rendered images.
 *
 * @author Karsten Philipp Boris Hahn
 *
 */
package io.github.struppigel.tools.visualizer.engine;
