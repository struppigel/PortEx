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

import io.github.struppigel.tools.sigscanner.SignatureMatch;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A signature match as shown in a {@link StructureMap}: a name, a file offset
 * and a length.
 * <p>
 * This class decouples the structure map from the signature scanner. Use
 * {@link #fromMatches(List)} to convert the matches of
 * {@link io.github.struppigel.parser.PEData#getSignatureMatches()}.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class SignatureHit {

    private final String name;
    private final long offset;
    private final long length;
    private final String locationLabel;

    /**
     * Creates a signature hit.
     *
     * @param name the name of the signature
     * @param offset the file offset of the match
     * @param length the number of matched bytes, a length of 0 is shown as one byte
     */
    public SignatureHit(String name, long offset, long length) {
        this(name, offset, length, "");
    }

    /**
     * Creates a signature hit.
     *
     * @param name the name of the signature
     * @param offset the file offset of the match
     * @param length the number of matched bytes, a length of 0 is shown as one byte
     * @param locationLabel where the signature matched, e.g. "overlay"
     */
    public SignatureHit(String name, long offset, long length, String locationLabel) {
        this.name = Objects.requireNonNull(name);
        this.offset = offset;
        this.length = length;
        this.locationLabel = Objects.requireNonNull(locationLabel);
    }

    /**
     * Converts a match of the signature scanner.
     *
     * @param match the signature match
     * @return the hit, absent if the match has no file offset, e.g. because
     *         the signature only has conditions
     */
    public static Optional<SignatureHit> of(SignatureMatch match) {
        if (!match.hasOffset() || match.getOffset() < 0) {
            return Optional.empty();
        }
        return Optional.of(new SignatureHit(match.getName(), match.getOffset(),
                match.getLength(), match.getLocationLabel()));
    }

    /**
     * Converts matches of the signature scanner, skipping matches without file
     * offset.
     *
     * @param matches the signature matches
     * @return the hits in the order of the matches
     */
    public static List<SignatureHit> fromMatches(List<SignatureMatch> matches) {
        List<SignatureHit> hits = new ArrayList<>();
        for (SignatureMatch match : matches) {
            Optional<SignatureHit> hit = of(match);
            if (hit.isPresent()) {
                hits.add(hit.get());
            }
        }
        return Collections.unmodifiableList(hits);
    }

    /**
     * @return the name of the signature
     */
    public String getName() {
        return name;
    }

    /**
     * @return the file offset of the match
     */
    public long getOffset() {
        return offset;
    }

    /**
     * @return the number of matched bytes, may be 0
     */
    public long getLength() {
        return length;
    }

    /**
     * @return where the signature matched, e.g. "overlay", empty if unknown
     */
    public String getLocationLabel() {
        return locationLabel;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SignatureHit)) return false;
        SignatureHit that = (SignatureHit) o;
        return offset == that.offset && length == that.length && name.equals(that.name)
                && locationLabel.equals(that.locationLabel);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, offset, length, locationLabel);
    }

    @Override
    public String toString() {
        return name + " " + StructureMap.hexRange(offset, offset + Math.max(1, length));
    }
}
