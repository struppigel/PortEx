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
 * The result of verifying a timestamp.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class TimestampVerification {

    private final Timestamp timestamp;
    private final VerificationStatus imprintStatus;
    private final String computedImprint;
    private final VerificationStatus messageDigestStatus;
    private final String computedMessageDigest;
    private final VerificationStatus signatureStatus;
    private final CertificateChain chain;

    TimestampVerification(Timestamp timestamp, VerificationStatus imprintStatus, String computedImprint,
                          VerificationStatus messageDigestStatus, String computedMessageDigest,
                          VerificationStatus signatureStatus, CertificateChain chain) {
        this.timestamp = timestamp;
        this.imprintStatus = imprintStatus;
        this.computedImprint = computedImprint;
        this.messageDigestStatus = messageDigestStatus;
        this.computedMessageDigest = computedMessageDigest;
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
     * @return the computed digest of the signature value as hex string, empty
     *         if the algorithm is not supported
     */
    public Optional<String> getComputedImprint() {
        return Optional.ofNullable(computedImprint);
    }

    /**
     * The messageDigest attribute of a countersignature is the imprint, so
     * this equals {@link #getImprintStatus()} for countersignatures.
     *
     * @return whether the messageDigest attribute of the timestamp signer
     *         equals the digest of the signed content
     */
    public VerificationStatus getMessageDigestStatus() {
        return messageDigestStatus;
    }

    /**
     * @return the computed digest of the content signed by the timestamp
     *         signer as hex string: the TSTInfo of RFC 3161 tokens, the
     *         signature value for countersignatures; empty if the signer has
     *         no messageDigest attribute or the algorithm is not supported
     */
    public Optional<String> getComputedMessageDigest() {
        return Optional.ofNullable(computedMessageDigest);
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
