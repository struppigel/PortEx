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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * An Authenticode signature: a PKCS#7 SignedData whose content is the digest
 * of the PE image (SpcIndirectDataContent).
 * <p>
 * Signatures can contain nested signatures, e.g. a SHA-256 signature nested
 * in a SHA-1 signature.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class AuthenticodeSignature {

    private final int entryIndex;
    private final int nestingLevel;
    private final int number;
    private final int parentNumber;
    private final DerElement contentInfo;
    private final String contentType;
    private final int version;
    private final List<AlgorithmId> digestAlgorithms;
    private final AlgorithmId imageDigestAlgorithm;
    private final DerElement imageDigest;
    private final DerElement indirectData;
    private final PageHashes pageHashes;
    private final List<AuthenticodeCertificate> certificates;
    private final List<SignerInfo> signers;
    private final List<AuthenticodeSignature> nestedSignatures;
    private final boolean berEncoded;
    private final List<CertificateIssue> issues;

    AuthenticodeSignature(int entryIndex, int nestingLevel, int number, int parentNumber,
                          DerElement contentInfo, String contentType, int version,
                          List<AlgorithmId> digestAlgorithms, AlgorithmId imageDigestAlgorithm,
                          DerElement imageDigest, DerElement indirectData, PageHashes pageHashes,
                          List<AuthenticodeCertificate> certificates, List<SignerInfo> signers,
                          List<AuthenticodeSignature> nestedSignatures, boolean berEncoded,
                          List<CertificateIssue> issues) {
        this.entryIndex = entryIndex;
        this.nestingLevel = nestingLevel;
        this.number = number;
        this.parentNumber = parentNumber;
        this.contentInfo = contentInfo;
        this.contentType = contentType;
        this.version = version;
        this.digestAlgorithms = Collections.unmodifiableList(new ArrayList<>(digestAlgorithms));
        this.imageDigestAlgorithm = imageDigestAlgorithm;
        this.imageDigest = imageDigest;
        this.indirectData = indirectData;
        this.pageHashes = pageHashes;
        this.certificates = Collections.unmodifiableList(new ArrayList<>(certificates));
        this.signers = Collections.unmodifiableList(new ArrayList<>(signers));
        this.nestedSignatures = Collections.unmodifiableList(new ArrayList<>(nestedSignatures));
        this.berEncoded = berEncoded;
        this.issues = Collections.unmodifiableList(new ArrayList<>(issues));
    }

    /**
     * @return the index of the WIN_CERTIFICATE that contains the signature
     */
    public int getEntryIndex() {
        return entryIndex;
    }

    /**
     * @return 0 for the signature of a WIN_CERTIFICATE, 1 for a signature
     *         nested in it, and so on
     */
    public int getNestingLevel() {
        return nestingLevel;
    }

    /**
     * @return the number of the signature in depth-first order, starting at 1
     */
    public int getNumber() {
        return number;
    }

    /**
     * @return a name for messages, e.g. "signature 2 (nested in 1)"
     */
    public String getLabel() {
        return "signature " + number + (parentNumber > 0 ? " (nested in " + parentNumber + ")" : "");
    }

    /**
     * @return the location of the ContentInfo
     */
    public PhysicalLocation getLocation() {
        return contentInfo.location();
    }

    /**
     * @return a copy of the DER encoding of the ContentInfo, which is the
     *         content of a .p7b file
     */
    public byte[] getEncoded() {
        return contentInfo.encoded();
    }

    /**
     * @return the content type of the signed content, 1.3.6.1.4.1.311.2.1.4
     *         (SpcIndirectDataContent) for Authenticode
     */
    public String getContentType() {
        return contentType;
    }

    /**
     * @return the SignedData version
     */
    public int getVersion() {
        return version;
    }

    /**
     * @return the digest algorithms listed in the SignedData
     */
    public List<AlgorithmId> getDigestAlgorithms() {
        return digestAlgorithms;
    }

    /**
     * @return the algorithm of the signed image digest
     */
    public Optional<AlgorithmId> getImageDigestAlgorithm() {
        return Optional.ofNullable(imageDigestAlgorithm);
    }

    /**
     * @return a copy of the signed digest of the PE image
     */
    public Optional<byte[]> getImageDigest() {
        return imageDigest == null ? Optional.<byte[]>empty() : Optional.of(imageDigest.content());
    }

    /**
     * @return the page hashes, if the signature has them
     */
    public Optional<PageHashes> getPageHashes() {
        return Optional.ofNullable(pageHashes);
    }

    /**
     * @return the embedded certificates
     */
    public List<AuthenticodeCertificate> getCertificates() {
        return certificates;
    }

    /**
     * @return all signers, Authenticode requires exactly one
     */
    public List<SignerInfo> getSigners() {
        return signers;
    }

    /**
     * @return the first signer, which Windows uses
     */
    public Optional<SignerInfo> getSigner() {
        return signers.isEmpty() ? Optional.<SignerInfo>empty() : Optional.of(signers.get(0));
    }

    /**
     * @return the signatures nested in this one
     */
    public List<AuthenticodeSignature> getNestedSignatures() {
        return nestedSignatures;
    }

    /**
     * @return true iff the signature uses BER features instead of DER
     */
    public boolean isBerEncoded() {
        return berEncoded;
    }

    /**
     * @return the parse issues of this signature, not including those of
     *         nested signatures
     */
    public List<CertificateIssue> getIssues() {
        return issues;
    }

    DerElement contentInfo() {
        return contentInfo;
    }

    DerElement imageDigestElement() {
        return imageDigest;
    }

    /**
     * @return the SpcIndirectDataContent SEQUENCE, null if missing
     */
    DerElement indirectDataElement() {
        return indirectData;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(getLabel());
        if (imageDigestAlgorithm != null) {
            sb.append(", ").append(imageDigestAlgorithm).append(" image digest");
        }
        if (!signers.isEmpty()) {
            sb.append(", ").append(signers.get(0));
        }
        return sb.toString();
    }
}
