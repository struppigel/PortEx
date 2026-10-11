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

import java.util.Optional;

/**
 * The result of verifying the signature of an embedded certificate with the
 * public key of its issuer, if the issuer is embedded too.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class CertificateVerification {

    private final AuthenticodeCertificate certificate;
    private final AuthenticodeCertificate issuer;
    private final VerificationStatus status;

    CertificateVerification(AuthenticodeCertificate certificate, AuthenticodeCertificate issuer,
                            VerificationStatus status) {
        this.certificate = certificate;
        this.issuer = issuer;
        this.status = status;
    }

    /**
     * @return the verified certificate
     */
    public AuthenticodeCertificate getCertificate() {
        return certificate;
    }

    /**
     * @return the embedded issuer whose key was used, empty if the issuer is
     *         not embedded
     */
    public Optional<AuthenticodeCertificate> getIssuer() {
        return Optional.ofNullable(issuer);
    }

    /**
     * @return VALID if the issuer signed the certificate, NOT_CHECKED if the
     *         issuer is not embedded
     */
    public VerificationStatus getStatus() {
        return status;
    }

    @Override
    public String toString() {
        return certificate.displayName() + ": " + status;
    }
}
