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

import io.github.struppigel.parser.Characteristic;

import java.util.Optional;

/**
 * The revisions of the WIN_CERTIFICATE structure (wRevision).
 *
 * @author Karsten Philipp Boris Hahn
 */
public enum WinCertRevision implements Characteristic {

    /**
     * Legacy version, only supported to verify legacy Authenticode
     * signatures.
     */
    REVISION_1_0(0x0100, "WIN_CERT_REVISION_1_0, legacy version", true),
    /** The current version */
    REVISION_2_0(0x0200, "WIN_CERT_REVISION_2_0, current version", false);

    private final long value;
    private final String description;
    private final boolean deprecated;

    WinCertRevision(long value, String description, boolean deprecated) {
        this.value = value;
        this.description = description;
        this.deprecated = deprecated;
    }

    /**
     * @param value the wRevision value
     * @return the revision, empty if the value is invalid
     */
    public static Optional<WinCertRevision> forValue(long value) {
        for (WinCertRevision revision : values()) {
            if (revision.value == value) {
                return Optional.of(revision);
            }
        }
        return Optional.empty();
    }

    @Override
    public boolean isReserved() {
        return false;
    }

    @Override
    public boolean isDeprecated() {
        return deprecated;
    }

    @Override
    public String getDescription() {
        return description;
    }

    @Override
    public long getValue() {
        return value;
    }
}
