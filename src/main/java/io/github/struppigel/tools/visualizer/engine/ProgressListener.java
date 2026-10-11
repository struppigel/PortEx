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

/**
 * Receives the progress of a long computation, e.g.
 * {@link ByteStatistics#compute(ProgressListener)}.
 *
 * @author Karsten Philipp Boris Hahn
 */
public interface ProgressListener {

    /** a listener that ignores progress */
    ProgressListener NONE = new ProgressListener() {
        @Override
        public void progress(long done, long total) {
        }
    };

    /**
     * Called on the computing thread whenever more data is available.
     *
     * @param done the number of bytes that are done
     * @param total the number of bytes in all
     */
    void progress(long done, long total);
}
