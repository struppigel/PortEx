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

/**
 * A validated ASN.1 element tree, the result of {@link DerReader#read}.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class DerDocument {

    private final DerElement root;
    private final long firstBerOffset;
    private final int trailingBytes;
    private final int elementCount;

    DerDocument(DerElement root, long firstBerOffset, int trailingBytes, int elementCount) {
        this.root = root;
        this.firstBerOffset = firstBerOffset;
        this.trailingBytes = trailingBytes;
        this.elementCount = elementCount;
    }

    /**
     * @return the outermost element
     */
    DerElement root() {
        return root;
    }

    /**
     * @return true iff BER features were used: indefinite lengths, non-minimal
     *         lengths or tag numbers
     */
    boolean isBer() {
        return firstBerOffset >= 0;
    }

    /**
     * @return the file offset of the first element that uses BER features, -1
     *         if none
     */
    long firstBerOffset() {
        return firstBerOffset;
    }

    /**
     * @return the number of bytes after the root element within the parsed
     *         range
     */
    int trailingBytes() {
        return trailingBytes;
    }

    /**
     * @return the number of elements in the tree
     */
    int elementCount() {
        return elementCount;
    }
}
