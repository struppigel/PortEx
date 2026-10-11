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

import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * A signer of a PKCS#7 SignedData: the Authenticode signer, a legacy
 * countersigner or the signer of an RFC 3161 timestamp token.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class SignerInfo {

    private final DerElement element;
    private final int version;
    private final String issuerName;
    private final byte[] serialBytes;
    private final byte[] subjectKeyIdentifier;
    private final AlgorithmId digestAlgorithm;
    private final AlgorithmId signatureAlgorithm;
    private final String jdkSignatureAlgorithm;
    private final List<SignatureAttribute> signedAttributes;
    private final List<SignatureAttribute> unauthenticatedAttributes;
    private final DerElement signedAttributesElement;
    private final DerElement messageDigest;
    private final Instant signingTime;
    private final String programName;
    private final String moreInfoUrl;
    private final List<Timestamp> timestamps;
    private final AuthenticodeCertificate signerCertificate;
    private final DerElement signatureValue;

    SignerInfo(DerElement element, int version, String issuerName, byte[] serialBytes,
               byte[] subjectKeyIdentifier, AlgorithmId digestAlgorithm, AlgorithmId signatureAlgorithm,
               String jdkSignatureAlgorithm, List<SignatureAttribute> signedAttributes,
               List<SignatureAttribute> unauthenticatedAttributes, DerElement signedAttributesElement,
               DerElement messageDigest, Instant signingTime, String programName, String moreInfoUrl,
               List<Timestamp> timestamps, AuthenticodeCertificate signerCertificate,
               DerElement signatureValue) {
        this.element = element;
        this.version = version;
        this.issuerName = issuerName;
        this.serialBytes = serialBytes;
        this.subjectKeyIdentifier = subjectKeyIdentifier;
        this.digestAlgorithm = digestAlgorithm;
        this.signatureAlgorithm = signatureAlgorithm;
        this.jdkSignatureAlgorithm = jdkSignatureAlgorithm;
        this.signedAttributes = Collections.unmodifiableList(new ArrayList<>(signedAttributes));
        this.unauthenticatedAttributes = Collections.unmodifiableList(new ArrayList<>(unauthenticatedAttributes));
        this.signedAttributesElement = signedAttributesElement;
        this.messageDigest = messageDigest;
        this.signingTime = signingTime;
        this.programName = programName;
        this.moreInfoUrl = moreInfoUrl;
        this.timestamps = Collections.unmodifiableList(new ArrayList<>(timestamps));
        this.signerCertificate = signerCertificate;
        this.signatureValue = signatureValue;
    }

    /**
     * @return the SignerInfo version, 1 for issuer and serial number, 3 for
     *         subject key identifier
     */
    public int getVersion() {
        return version;
    }

    /**
     * @return the issuer name of the signer certificate in RFC 2253 format,
     *         empty string if the signer is identified by a subject key
     *         identifier
     */
    public String getIssuerName() {
        return issuerName;
    }

    /**
     * @return the serial number of the signer certificate, empty if the signer
     *         is identified by a subject key identifier
     */
    public Optional<BigInteger> getSerialNumber() {
        return serialBytes == null ? Optional.<BigInteger>empty() : Optional.of(new BigInteger(serialBytes));
    }

    /**
     * @return the serial number of the signer certificate as hex string of its
     *         encoded bytes, empty if the signer is identified by a subject key
     *         identifier
     */
    public Optional<String> getSerialNumberHex() {
        return serialBytes == null ? Optional.<String>empty() : Optional.of(Hex.of(serialBytes));
    }

    /**
     * @return the subject key identifier of the signer certificate as hex
     *         string, if the signer is identified by it
     */
    public Optional<String> getSubjectKeyIdentifierHex() {
        return subjectKeyIdentifier == null ? Optional.<String>empty()
                : Optional.of(Hex.of(subjectKeyIdentifier));
    }

    /**
     * @return the digest algorithm of the signer
     */
    public AlgorithmId getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * @return the signature (digest encryption) algorithm of the signer
     */
    public AlgorithmId getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * @return the JDK name of the signature algorithm, e.g. "SHA256withRSA",
     *         empty if unsupported
     */
    public Optional<String> getJdkSignatureAlgorithm() {
        return Optional.ofNullable(jdkSignatureAlgorithm);
    }

    /**
     * @return the signed (authenticated) attributes
     */
    public List<SignatureAttribute> getSignedAttributes() {
        return signedAttributes;
    }

    /**
     * @return the unauthenticated attributes, which are not covered by the
     *         signature
     */
    public List<SignatureAttribute> getUnauthenticatedAttributes() {
        return unauthenticatedAttributes;
    }

    /**
     * @return a copy of the messageDigest attribute value
     */
    public Optional<byte[]> getMessageDigest() {
        return messageDigest == null ? Optional.<byte[]>empty() : Optional.of(messageDigest.content());
    }

    /**
     * @return the signingTime attribute
     */
    public Optional<Instant> getSigningTime() {
        return Optional.ofNullable(signingTime);
    }

    /**
     * @return the program name of the SpcSpOpusInfo attribute
     */
    public Optional<String> getProgramName() {
        return Optional.ofNullable(programName);
    }

    /**
     * @return the more info URL of the SpcSpOpusInfo attribute
     */
    public Optional<String> getMoreInfoUrl() {
        return Optional.ofNullable(moreInfoUrl);
    }

    /**
     * @return the timestamps (countersignatures) of this signer
     */
    public List<Timestamp> getTimestamps() {
        return timestamps;
    }

    /**
     * @return the certificate of the signer, empty if it is not embedded
     */
    public Optional<AuthenticodeCertificate> getSignerCertificate() {
        return Optional.ofNullable(signerCertificate);
    }

    /**
     * @return the location of the SignerInfo
     */
    public PhysicalLocation getLocation() {
        return element.location();
    }

    /**
     * @return the location of the signature value (encryptedDigest)
     */
    public PhysicalLocation getSignatureValueLocation() {
        return signatureValue.location();
    }

    /**
     * @return a copy of the signature value (encryptedDigest)
     */
    public byte[] getSignatureValue() {
        return signatureValue.content();
    }

    /**
     * @return the signing time of the first timestamp with a time, else the
     *         signingTime attribute
     */
    public Optional<Instant> getEffectiveSigningTime() {
        for (Timestamp t : timestamps) {
            if (t.getTime().isPresent()) {
                return t.getTime();
            }
        }
        return getSigningTime();
    }

    DerElement element() {
        return element;
    }

    DerElement signedAttributesElement() {
        return signedAttributesElement;
    }

    DerElement messageDigestElement() {
        return messageDigest;
    }

    DerElement signatureValueElement() {
        return signatureValue;
    }

    byte[] subjectKeyIdentifier() {
        return subjectKeyIdentifier == null ? null : Arrays.copyOf(subjectKeyIdentifier,
                subjectKeyIdentifier.length);
    }

    @Override
    public String toString() {
        String who = signerCertificate != null ? signerCertificate.displayName() : issuerName;
        return "signer " + who + " (" + digestAlgorithm + ", " + signatureAlgorithm + ")";
    }
}
