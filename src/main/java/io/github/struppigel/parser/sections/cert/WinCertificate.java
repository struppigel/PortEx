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

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

/**
 * One entry of the certificate table, a WIN_CERTIFICATE structure.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class WinCertificate {

    /** size of the WIN_CERTIFICATE header in bytes */
    public static final int HEADER_SIZE = 8;

    private final int index;
    private final long offset;
    private final Map<WinCertificateKey, StandardField> fields;
    private final PhysicalLocation location;
    private final PhysicalLocation contentLocation;
    private final PhysicalLocation paddingLocation;
    private final boolean truncated;
    private final byte[] content;
    private final AuthenticodeSignature signature;
    private final AuthenticodeCertificate x509;

    WinCertificate(int index, long offset, Map<WinCertificateKey, StandardField> fields,
                   PhysicalLocation location, PhysicalLocation contentLocation,
                   PhysicalLocation paddingLocation, boolean truncated, byte[] content,
                   AuthenticodeSignature signature, AuthenticodeCertificate x509) {
        this.index = index;
        this.offset = offset;
        this.fields = Collections.unmodifiableMap(new EnumMap<>(fields));
        this.location = location;
        this.contentLocation = contentLocation;
        this.paddingLocation = paddingLocation;
        this.truncated = truncated;
        this.content = content;
        this.signature = signature;
        this.x509 = x509;
    }

    /**
     * @return the index of the entry in the table, starting at 0
     */
    public int getIndex() {
        return index;
    }

    /**
     * @return the file offset of the entry
     */
    public long getOffset() {
        return offset;
    }

    /**
     * @return dwLength, the declared length of the entry including the header
     */
    public long getLength() {
        return getField(WinCertificateKey.LENGTH).getValue();
    }

    /**
     * @return the wRevision value
     */
    public long getRevisionValue() {
        return getField(WinCertificateKey.REVISION).getValue();
    }

    /**
     * @return the revision, empty if wRevision is invalid
     */
    public Optional<WinCertRevision> getRevision() {
        return WinCertRevision.forValue(getRevisionValue());
    }

    /**
     * @return the wCertificateType value
     */
    public long getCertificateTypeValue() {
        return getField(WinCertificateKey.CERTIFICATE_TYPE).getValue();
    }

    /**
     * @return the certificate type, empty if wCertificateType is invalid
     */
    public Optional<WinCertType> getCertificateType() {
        return WinCertType.forValue(getCertificateTypeValue());
    }

    /**
     * @return the header fields
     */
    public Map<WinCertificateKey, StandardField> getHeaderFields() {
        return fields;
    }

    /**
     * @param key the header field key
     * @return the header field
     */
    public StandardField getField(WinCertificateKey key) {
        return fields.get(key);
    }

    /**
     * @return the location of the entry as far as it is within the table and
     *         the file
     */
    public PhysicalLocation getPhysicalLocation() {
        return location;
    }

    /**
     * @return the location of bCertificate, the content after the header
     */
    public PhysicalLocation getContentLocation() {
        return contentLocation;
    }

    /**
     * @return the location of the bytes after the PKCS#7 structure up to the
     *         next 8-byte boundary, empty if there are none
     */
    public Optional<PhysicalLocation> getPaddingLocation() {
        return Optional.ofNullable(paddingLocation);
    }

    /**
     * @return true iff dwLength exceeds the available data
     */
    public boolean isTruncated() {
        return truncated;
    }

    /**
     * @return a copy of bCertificate as far as it was read, at most
     *         {@link CertificateTable#MAX_TABLE_READ_SIZE} bytes
     */
    public byte[] getContent() {
        return Arrays.copyOf(content, content.length);
    }

    /**
     * @return the Authenticode signature of a WIN_CERT_TYPE_PKCS_SIGNED_DATA
     *         entry, empty for other types or if it is malformed
     */
    public Optional<AuthenticodeSignature> getSignature() {
        return Optional.ofNullable(signature);
    }

    /**
     * @return the certificate of a WIN_CERT_TYPE_X509 entry
     */
    public Optional<AuthenticodeCertificate> getX509Certificate() {
        return Optional.ofNullable(x509);
    }

    @Override
    public String toString() {
        return "WIN_CERTIFICATE " + index + " at 0x" + Long.toHexString(offset) + ", length 0x"
                + Long.toHexString(getLength()) + ", revision 0x" + Long.toHexString(getRevisionValue())
                + ", type " + getCertificateType().map(Enum::name).orElse("0x"
                + Long.toHexString(getCertificateTypeValue()));
    }
}
