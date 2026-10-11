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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A certificate chain built from the embedded certificates, starting with
 * the signer certificate. The chain ends at a self-signed certificate or at
 * the first certificate whose issuer is not embedded.
 * <p>
 * The status only covers the links within the chain: whether each certificate
 * was signed by the next one. It does not say whether the last certificate is
 * trusted.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class CertificateChain {

    private final List<AuthenticodeCertificate> certificates;
    private final VerificationStatus status;

    CertificateChain(List<AuthenticodeCertificate> certificates, VerificationStatus status) {
        this.certificates = Collections.unmodifiableList(new ArrayList<>(certificates));
        this.status = status;
    }

    /**
     * @return the certificates, signer certificate first; empty if the signer
     *         certificate is not embedded
     */
    public List<AuthenticodeCertificate> getCertificates() {
        return certificates;
    }

    /**
     * @return true iff the last certificate is self-issued
     */
    public boolean endsInSelfSigned() {
        return !certificates.isEmpty() && certificates.get(certificates.size() - 1).isSelfIssued();
    }

    /**
     * @return INVALID if a certificate was not signed by the next one,
     *         UNVERIFIABLE if a link could not be checked, VALID otherwise
     */
    public VerificationStatus getStatus() {
        return status;
    }

    @Override
    public String toString() {
        List<String> names = new ArrayList<>();
        for (AuthenticodeCertificate c : certificates) {
            names.add(c.displayName());
        }
        return String.join(" -> ", names) + " (" + status + ")";
    }
}
