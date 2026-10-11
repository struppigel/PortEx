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
import io.github.struppigel.parser.StandardField;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * A problem that was found while parsing or verifying the certificate table.
 * <p>
 * Issues describe malformed, manipulated or unusual data. The anomaly scanner
 * turns them into anomalies, but Java applications can use them directly.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class CertificateIssue {

    private final CertificateIssueType type;
    private final String description;
    private final List<PhysicalLocation> locations;
    private final StandardField headerField;
    private final AuthenticodeFieldKey fieldKey;

    CertificateIssue(CertificateIssueType type, String description, List<PhysicalLocation> locations,
                     StandardField headerField, AuthenticodeFieldKey fieldKey) {
        this.type = type;
        this.description = description;
        this.locations = Collections.unmodifiableList(new ArrayList<>(locations));
        this.headerField = headerField;
        this.fieldKey = fieldKey;
    }

    /**
     * @return the kind of the issue
     */
    public CertificateIssueType getType() {
        return type;
    }

    /**
     * @return a description of the issue
     */
    public String getDescription() {
        return description;
    }

    /**
     * @return the file locations the issue concerns, may be empty
     */
    public List<PhysicalLocation> getLocations() {
        return locations;
    }

    /**
     * @return the WIN_CERTIFICATE header field the issue concerns
     */
    public Optional<StandardField> getHeaderField() {
        return Optional.ofNullable(headerField);
    }

    /**
     * @return the signature field the issue concerns
     */
    public Optional<AuthenticodeFieldKey> getFieldKey() {
        return Optional.ofNullable(fieldKey);
    }

    @Override
    public String toString() {
        return description;
    }
}
