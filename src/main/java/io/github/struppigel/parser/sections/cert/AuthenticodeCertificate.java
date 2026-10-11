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
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;

/**
 * An X.509 certificate that is embedded in a signature.
 * <p>
 * The fields are read by PortEx's own bounded parser, so they are available
 * even if the JDK rejects the certificate. {@link #getX509Certificate()}
 * additionally offers the JDK's view of the certificate.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class AuthenticodeCertificate {

    private final DerElement element;
    private final DerElement tbs;
    private final int version;
    private final byte[] serialBytes;
    private final DerElement issuerName;
    private final DerElement subjectName;
    private final String issuer;
    private final String subject;
    private final String issuerCommonName;
    private final String subjectCommonName;
    private final Instant notBefore;
    private final Instant notAfter;
    private final AlgorithmId signatureAlgorithm;
    private final AlgorithmId publicKeyAlgorithm;
    private final DerElement subjectPublicKeyInfo;
    private final int publicKeySize;
    private final String namedCurve;
    private final boolean explicitCurveParameters;
    private final DerElement signatureValue;
    private final byte[] subjectKeyIdentifier;
    private final String sha1Thumbprint;
    private final String sha256Thumbprint;
    private final X509Certificate x509;

    AuthenticodeCertificate(DerElement element, DerElement tbs, int version, byte[] serialBytes,
                            DerElement issuerName, DerElement subjectName, String issuer, String subject,
                            String issuerCommonName, String subjectCommonName, Instant notBefore,
                            Instant notAfter, AlgorithmId signatureAlgorithm, AlgorithmId publicKeyAlgorithm,
                            DerElement subjectPublicKeyInfo, int publicKeySize, String namedCurve,
                            boolean explicitCurveParameters, DerElement signatureValue,
                            byte[] subjectKeyIdentifier, String sha1Thumbprint, String sha256Thumbprint,
                            X509Certificate x509) {
        this.element = element;
        this.tbs = tbs;
        this.version = version;
        this.serialBytes = serialBytes;
        this.issuerName = issuerName;
        this.subjectName = subjectName;
        this.issuer = issuer;
        this.subject = subject;
        this.issuerCommonName = issuerCommonName;
        this.subjectCommonName = subjectCommonName;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.signatureAlgorithm = signatureAlgorithm;
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
        this.publicKeySize = publicKeySize;
        this.namedCurve = namedCurve;
        this.explicitCurveParameters = explicitCurveParameters;
        this.signatureValue = signatureValue;
        this.subjectKeyIdentifier = subjectKeyIdentifier;
        this.sha1Thumbprint = sha1Thumbprint;
        this.sha256Thumbprint = sha256Thumbprint;
        this.x509 = x509;
    }

    /**
     * @return a copy of the DER encoding of the certificate
     */
    public byte[] getEncoded() {
        return element.encoded();
    }

    /**
     * @return the location of the certificate in the file
     */
    public PhysicalLocation getLocation() {
        return element.location();
    }

    /**
     * @return the X.509 version, 1 to 3
     */
    public int getVersion() {
        return version;
    }

    /**
     * @return the serial number
     */
    public BigInteger getSerialNumber() {
        return new BigInteger(serialBytes);
    }

    /**
     * @return the serial number as hex string of its encoded bytes
     */
    public String getSerialNumberHex() {
        return Hex.of(serialBytes);
    }

    /**
     * @return the subject name in RFC 2253 format
     */
    public String getSubjectName() {
        return subject;
    }

    /**
     * @return the issuer name in RFC 2253 format
     */
    public String getIssuerName() {
        return issuer;
    }

    /**
     * @return the common name (CN) of the subject
     */
    public Optional<String> getSubjectCommonName() {
        return Optional.ofNullable(subjectCommonName);
    }

    /**
     * @return the common name (CN) of the issuer
     */
    public Optional<String> getIssuerCommonName() {
        return Optional.ofNullable(issuerCommonName);
    }

    /**
     * @return the start of the validity period
     */
    public Optional<Instant> getNotBefore() {
        return Optional.ofNullable(notBefore);
    }

    /**
     * @return the end of the validity period
     */
    public Optional<Instant> getNotAfter() {
        return Optional.ofNullable(notAfter);
    }

    /**
     * @param time the time to check
     * @return true iff the validity period is known and contains the time
     */
    public boolean isValidAt(Instant time) {
        return notBefore != null && notAfter != null
                && !time.isBefore(notBefore) && !time.isAfter(notAfter);
    }

    /**
     * @return the algorithm that the issuer used to sign this certificate
     */
    public AlgorithmId getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * @return the algorithm of the subject public key
     */
    public AlgorithmId getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }

    /**
     * @return the size of the public key in bits, -1 if unknown
     */
    public int getPublicKeySize() {
        return publicKeySize;
    }

    /**
     * @return the name of the curve of an EC key, e.g. "secp256r1", or its
     *         OID if the name is unknown
     */
    public Optional<String> getNamedCurve() {
        return Optional.ofNullable(namedCurve);
    }

    /**
     * EC keys must use named curves (RFC 5480). Explicit curve parameters were
     * used to spoof certificates (CurveBall, CVE-2020-0601).
     *
     * @return true iff the certificate has an EC key with explicit or implicit
     *         curve parameters instead of a named curve
     */
    public boolean hasExplicitCurveParameters() {
        return explicitCurveParameters;
    }

    /**
     * @return true iff subject and issuer are equal
     */
    public boolean isSelfIssued() {
        return subjectName.equalEncoding(issuerName);
    }

    /**
     * @return the SHA-1 thumbprint as hex string
     */
    public String getSha1Thumbprint() {
        return sha1Thumbprint;
    }

    /**
     * @return the SHA-256 thumbprint as hex string
     */
    public String getSha256Thumbprint() {
        return sha256Thumbprint;
    }

    /**
     * @return the certificate as parsed by the JDK, empty if the JDK rejects
     *         it or it is larger than {@link CertificateTable#MAX_CERTIFICATE_SIZE}
     */
    public Optional<X509Certificate> getX509Certificate() {
        return Optional.ofNullable(x509);
    }

    DerElement element() {
        return element;
    }

    DerElement tbs() {
        return tbs;
    }

    DerElement issuerNameElement() {
        return issuerName;
    }

    DerElement subjectNameElement() {
        return subjectName;
    }

    DerElement subjectPublicKeyInfo() {
        return subjectPublicKeyInfo;
    }

    DerElement signatureValue() {
        return signatureValue;
    }

    byte[] serialBytes() {
        return serialBytes;
    }

    /**
     * @return the subject key identifier extension value, null if absent
     */
    byte[] subjectKeyIdentifier() {
        return subjectKeyIdentifier == null ? null : Arrays.copyOf(subjectKeyIdentifier,
                subjectKeyIdentifier.length);
    }

    /**
     * @return a short name for messages, the subject CN or the subject
     */
    String displayName() {
        return subjectCommonName != null ? subjectCommonName : subject;
    }

    @Override
    public String toString() {
        return "certificate " + displayName() + ", issued by "
                + (issuerCommonName != null ? issuerCommonName : issuer)
                + ", serial " + getSerialNumberHex();
    }
}
