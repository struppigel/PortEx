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
package io.github.struppigel.parser.sections.cert;

import io.github.struppigel.parser.PhysicalLocation;

/**
 * The page hashes of a signature. PortEx reports them, but does not verify
 * them.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class PageHashes {

    private final int version;
    private final String digestAlgorithmName;
    private final long entryCount;
    private final boolean wellFormed;
    private final PhysicalLocation location;

    PageHashes(int version, String digestAlgorithmName, long entryCount, boolean wellFormed,
               PhysicalLocation location) {
        this.version = version;
        this.digestAlgorithmName = digestAlgorithmName;
        this.entryCount = entryCount;
        this.wellFormed = wellFormed;
        this.location = location;
    }

    /**
     * @return 1 for SHA-1 page hashes, 2 for SHA-256 page hashes
     */
    public int getVersion() {
        return version;
    }

    /**
     * @return the digest algorithm of the page hashes, e.g. "SHA-256"
     */
    public String getDigestAlgorithmName() {
        return digestAlgorithmName;
    }

    /**
     * @return the number of page hash entries (offset and digest)
     */
    public long getEntryCount() {
        return entryCount;
    }

    /**
     * @return true iff the data consists of whole entries
     */
    public boolean isWellFormed() {
        return wellFormed;
    }

    /**
     * @return the location of the page hash data
     */
    public PhysicalLocation getLocation() {
        return location;
    }

    @Override
    public String toString() {
        return "page hashes v" + version + " (" + digestAlgorithmName + "), " + entryCount + " entries";
    }
}
