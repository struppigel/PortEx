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
 * The result of verifying a timestamp.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class TimestampVerification {

    private final Timestamp timestamp;
    private final VerificationStatus imprintStatus;
    private final VerificationStatus signatureStatus;
    private final CertificateChain chain;

    TimestampVerification(Timestamp timestamp, VerificationStatus imprintStatus,
                          VerificationStatus signatureStatus, CertificateChain chain) {
        this.timestamp = timestamp;
        this.imprintStatus = imprintStatus;
        this.signatureStatus = signatureStatus;
        this.chain = chain;
    }

    /**
     * @return the verified timestamp
     */
    public Timestamp getTimestamp() {
        return timestamp;
    }

    /**
     * @return whether the timestamp covers the signature value of the signer
     */
    public VerificationStatus getImprintStatus() {
        return imprintStatus;
    }

    /**
     * @return whether the timestamp signer signed the timestamp, including the
     *         message digest of RFC 3161 tokens
     */
    public VerificationStatus getSignatureStatus() {
        return signatureStatus;
    }

    /**
     * @return the chain of the timestamp signer certificate
     */
    public CertificateChain getChain() {
        return chain;
    }

    /**
     * @return INVALID if a check failed, VALID if imprint and signature are
     *         valid and the chain is not invalid, UNVERIFIABLE otherwise
     */
    public VerificationStatus getStatus() {
        if (imprintStatus == VerificationStatus.INVALID || signatureStatus == VerificationStatus.INVALID
                || chain.getStatus() == VerificationStatus.INVALID) {
            return VerificationStatus.INVALID;
        }
        if (imprintStatus == VerificationStatus.VALID && signatureStatus == VerificationStatus.VALID) {
            return VerificationStatus.VALID;
        }
        return VerificationStatus.UNVERIFIABLE;
    }

    @Override
    public String toString() {
        return timestamp + ": " + getStatus();
    }
}
