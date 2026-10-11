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
 * The certificate types of the WIN_CERTIFICATE structure (wCertificateType).
 * <p>
 * Windows Authenticode only supports {@link #PKCS_SIGNED_DATA}. The PE/COFF
 * specification lists the other values as defined but not supported.
 *
 * @author Karsten Philipp Boris Hahn
 */
public enum WinCertType implements Characteristic {

    /** WIN_CERT_TYPE_X509, an X.509 certificate, not supported */
    X509(1, "WIN_CERT_TYPE_X509, X.509 certificate (not supported)", false),
    /** WIN_CERT_TYPE_PKCS_SIGNED_DATA, a PKCS#7 SignedData structure */
    PKCS_SIGNED_DATA(2, "WIN_CERT_TYPE_PKCS_SIGNED_DATA, PKCS#7 SignedData", false),
    /** WIN_CERT_TYPE_RESERVED_1, reserved */
    RESERVED_1(3, "WIN_CERT_TYPE_RESERVED_1 (reserved)", true),
    /** WIN_CERT_TYPE_TS_STACK_SIGNED, terminal server protocol stack, not supported */
    TS_STACK_SIGNED(4, "WIN_CERT_TYPE_TS_STACK_SIGNED, terminal server protocol stack certificate (not supported)", false);

    private final long value;
    private final String description;
    private final boolean reserved;

    WinCertType(long value, String description, boolean reserved) {
        this.value = value;
        this.description = description;
        this.reserved = reserved;
    }

    /**
     * @param value the wCertificateType value
     * @return the certificate type, empty if the value is invalid
     */
    public static Optional<WinCertType> forValue(long value) {
        for (WinCertType type : values()) {
            if (type.value == value) {
                return Optional.of(type);
            }
        }
        return Optional.empty();
    }

    /**
     * @return true iff Windows Authenticode uses certificates of this type
     */
    public boolean isSupportedByAuthenticode() {
        return this == PKCS_SIGNED_DATA;
    }

    @Override
    public boolean isReserved() {
        return reserved;
    }

    @Override
    public boolean isDeprecated() {
        return false;
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
