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
import java.util.Optional;

/**
 * The integrity checks of one Authenticode signature.
 * <p>
 * VALID means integrity only: the image was not modified after signing and
 * the signature and embedded certificates are consistent. No trust,
 * revocation or expiry policy is applied.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class VerificationResult {

    private final AuthenticodeSignature signature;
    private final VerificationStatus imageDigestStatus;
    private final String computedImageDigest;
    private final VerificationStatus messageDigestStatus;
    private final VerificationStatus signerSignatureStatus;
    private final CertificateChain signerChain;
    private final List<CertificateVerification> certificateVerifications;
    private final List<TimestampVerification> timestampVerifications;
    private final List<CertificateIssue> issues;

    VerificationResult(AuthenticodeSignature signature, VerificationStatus imageDigestStatus,
                       String computedImageDigest, VerificationStatus messageDigestStatus,
                       VerificationStatus signerSignatureStatus, CertificateChain signerChain,
                       List<CertificateVerification> certificateVerifications,
                       List<TimestampVerification> timestampVerifications, List<CertificateIssue> issues) {
        this.signature = signature;
        this.imageDigestStatus = imageDigestStatus;
        this.computedImageDigest = computedImageDigest;
        this.messageDigestStatus = messageDigestStatus;
        this.signerSignatureStatus = signerSignatureStatus;
        this.signerChain = signerChain;
        this.certificateVerifications = Collections.unmodifiableList(new ArrayList<>(certificateVerifications));
        this.timestampVerifications = Collections.unmodifiableList(new ArrayList<>(timestampVerifications));
        this.issues = Collections.unmodifiableList(new ArrayList<>(issues));
    }

    /**
     * @return the verified signature
     */
    public AuthenticodeSignature getSignature() {
        return signature;
    }

    /**
     * @return whether the computed digest of the image equals the signed one
     */
    public VerificationStatus getImageDigestStatus() {
        return imageDigestStatus;
    }

    /**
     * @return the computed image digest as hex string, empty if the algorithm
     *         is not supported
     */
    public Optional<String> getComputedImageDigest() {
        return Optional.ofNullable(computedImageDigest);
    }

    /**
     * @return whether the messageDigest attribute equals the digest of the
     *         signed content
     */
    public VerificationStatus getMessageDigestStatus() {
        return messageDigestStatus;
    }

    /**
     * @return whether the signature of the signer is valid
     */
    public VerificationStatus getSignerSignatureStatus() {
        return signerSignatureStatus;
    }

    /**
     * @return the chain of the signer certificate within the embedded
     *         certificates
     */
    public CertificateChain getSignerChain() {
        return signerChain;
    }

    /**
     * @return one verification per embedded certificate, in the order of
     *         {@link AuthenticodeSignature#getCertificates()}
     */
    public List<CertificateVerification> getCertificateVerifications() {
        return certificateVerifications;
    }

    /**
     * @return one verification per timestamp of the first signer
     */
    public List<TimestampVerification> getTimestampVerifications() {
        return timestampVerifications;
    }

    /**
     * @return the issues found while verifying this signature
     */
    public List<CertificateIssue> getIssues() {
        return issues;
    }

    /**
     * Combines the checks. Timestamps do not change the status.
     *
     * @return INVALID if the image digest, the message digest, the signer
     *         signature or a link of the signer chain is invalid; VALID if
     *         all of them are valid; UNVERIFIABLE otherwise
     */
    public VerificationStatus getStatus() {
        VerificationStatus chain = signerChain.getStatus();
        if (imageDigestStatus == VerificationStatus.INVALID || messageDigestStatus == VerificationStatus.INVALID
                || signerSignatureStatus == VerificationStatus.INVALID || chain == VerificationStatus.INVALID) {
            return VerificationStatus.INVALID;
        }
        if (imageDigestStatus == VerificationStatus.VALID && messageDigestStatus == VerificationStatus.VALID
                && signerSignatureStatus == VerificationStatus.VALID && chain == VerificationStatus.VALID) {
            return VerificationStatus.VALID;
        }
        return VerificationStatus.UNVERIFIABLE;
    }

    @Override
    public String toString() {
        return signature.getLabel() + ": " + getStatus() + " (image digest " + imageDigestStatus
                + ", message digest " + messageDigestStatus + ", signer signature " + signerSignatureStatus
                + ", chain " + signerChain.getStatus() + ")";
    }
}
