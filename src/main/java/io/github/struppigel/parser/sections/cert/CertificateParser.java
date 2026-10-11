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

import io.github.struppigel.parser.AnalysisInterruptedException;
import io.github.struppigel.parser.sections.cert.ParseContext.IssueSink;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Optional;

/**
 * Parses X.509 certificates with PortEx's own bounded DER reader and,
 * additionally, with the JDK.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class CertificateParser {

    private CertificateParser() {
    }

    /**
     * @param cert the Certificate SEQUENCE
     * @param sink receives the issues
     * @return the parsed certificate
     * @throws DerException if the certificate is malformed
     */
    static AuthenticodeCertificate parse(DerElement cert, IssueSink sink) throws DerException {
        cert.expectSequence();
        DerElement tbs = cert.child(0).expectSequence();
        DerElement outerAlgorithm = cert.child(1);
        AlgorithmId signatureAlgorithm = signatureAlgorithm(outerAlgorithm, sink);
        DerElement signatureValue = cert.child(2).expect(DerElement.BIT_STRING);
        signatureValue.unusedBits();

        int i = 0;
        int version = 1;
        if (tbs.child(0).isContext(0)) {
            version = tbs.child(0).explicitContent().asSmallInteger() + 1;
            i++;
        }
        DerElement serialElement = tbs.child(i++);
        byte[] serial = serialElement.integerBytes(CertificateTable.MAX_INTEGER_LENGTH);
        tbs.child(i++).expectSequence(); // inner signature algorithm
        DerElement issuer = tbs.child(i++).expectSequence();
        DerElement validity = tbs.child(i++).expectSequence();
        DerElement subject = tbs.child(i++).expectSequence();
        DerElement spki = tbs.child(i++).expectSequence();
        byte[] ski = null;
        for (; i < tbs.childCount(); i++) {
            DerElement e = tbs.child(i);
            if (e.isContext(3)) {
                ski = subjectKeyIdentifier(e.explicitContent(), sink);
            }
        }

        String subjectName = NameRenderer.render(subject);
        String subjectCn = NameRenderer.commonName(subject).orElse(null);
        String label = "certificate " + (subjectCn != null ? subjectCn : subjectName);
        if (serial.length > CertificateTable.MAX_SERIAL_LENGTH) {
            sink.add(CertificateIssueType.OVERSIZED_SERIAL, label + ": serial number has " + serial.length
                            + " bytes, at most " + CertificateTable.MAX_SERIAL_LENGTH + " are allowed",
                    serialElement.location(), AuthenticodeFieldKey.CERTIFICATE_SERIAL_NUMBER);
        }

        Instant notBefore = validity.optChild(0).flatMap(DerElement::asTime).orElse(null);
        Instant notAfter = validity.optChild(1).flatMap(DerElement::asTime).orElse(null);

        AlgorithmId keyAlgorithm = sink.algorithm(spki.child(0), false);
        DerElement keyBits = spki.child(1).expect(DerElement.BIT_STRING);
        keyBits.unusedBits();
        int keySize = -1;
        String curve = null;
        boolean explicitCurve = false;
        switch (keyAlgorithm.getOid()) {
            case Oids.RSA_ENCRYPTION:
            case Oids.RSASSA_PSS:
                keySize = rsaModulusBits(keyBits);
                break;
            case Oids.EC_PUBLIC_KEY:
                DerElement params = keyAlgorithm.parameters();
                if (params != null && params.isUniversal(DerElement.OID)) {
                    String curveOid = sink.oid(params);
                    curve = Oids.nameOrOid(curveOid);
                    keySize = curveBits(curveOid, keyBits);
                } else {
                    explicitCurve = true;
                    keySize = (keyBits.contentLength() - 2) / 2 * 8;
                    sink.add(CertificateIssueType.EXPLICIT_EC_PARAMETERS, label
                                    + ": EC public key with explicit curve parameters instead of a named curve"
                                    + " (CurveBall, CVE-2020-0601)",
                            spki.location(), AuthenticodeFieldKey.CERTIFICATE_PUBLIC_KEY);
                }
                break;
            case Oids.DSA:
                keySize = dsaPrimeBits(keyAlgorithm.parameters());
                break;
            default:
                break;
        }

        return new AuthenticodeCertificate(cert, tbs, version, serial, issuer, subject,
                NameRenderer.render(issuer), subjectName, NameRenderer.commonName(issuer).orElse(null),
                subjectCn, notBefore, notAfter, signatureAlgorithm, keyAlgorithm, spki, keySize, curve,
                explicitCurve, signatureValue, ski, thumbprint("SHA-1", cert), thumbprint("SHA-256", cert),
                toX509(cert, sink.context().certificateFactory()));
    }

    private static AlgorithmId signatureAlgorithm(DerElement element, IssueSink sink) throws DerException {
        AlgorithmId id = sink.algorithm(element, false);
        String jdk = Algorithms.signatureJdkName(id.getOid(), null).orElse(null);
        return new AlgorithmId(id.getOid(), jdk, id.parameters(), id.getLocation());
    }

    private static byte[] subjectKeyIdentifier(DerElement extensions, IssueSink sink) throws DerException {
        for (DerElement extension : extensions.children()) {
            if (!extension.isSequence() || extension.childCount() < 2) {
                continue;
            }
            if (Oids.SUBJECT_KEY_IDENTIFIER.equals(sink.oid(extension.child(0)))) {
                DerElement value = extension.child(extension.childCount() - 1);
                try {
                    return value.parseEncapsulated().root().asOctets(CertificateTable.MAX_INTEGER_LENGTH);
                } catch (DerException e) {
                    return null;
                }
            }
        }
        return null;
    }

    private static int rsaModulusBits(DerElement keyBits) {
        try {
            DerElement key = keyBits.parseEncapsulated().root().expectSequence();
            BigInteger modulus = key.child(0).asInteger(CertificateTable.MAX_INTEGER_LENGTH);
            return modulus.bitLength();
        } catch (DerException e) {
            return -1;
        }
    }

    private static int curveBits(String curveOid, DerElement keyBits) {
        switch (curveOid) {
            case Oids.SECP256R1:
            case Oids.SECP256K1:
                return 256;
            case Oids.SECP384R1:
                return 384;
            case Oids.SECP521R1:
                return 521;
            default:
                // uncompressed point: unused bits byte, 0x04, x, y
                return keyBits.contentLength() > 2 ? (keyBits.contentLength() - 2) / 2 * 8 : -1;
        }
    }

    private static int dsaPrimeBits(DerElement params) {
        if (params == null || !params.isSequence()) {
            return -1;
        }
        try {
            return params.child(0).asInteger(CertificateTable.MAX_INTEGER_LENGTH).bitLength();
        } catch (DerException e) {
            return -1;
        }
    }

    private static String thumbprint(String algorithm, DerElement cert) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            cert.updateEncoded(md);
            return Hex.of(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(algorithm + " is not available", e);
        }
    }

    /**
     * Lets the JDK parse the certificate. Malformed certificates and those
     * larger than {@link CertificateTable#MAX_CERTIFICATE_SIZE} are not
     * passed to it.
     *
     * @return the JDK certificate, null if not available
     */
    static X509Certificate toX509(DerElement cert, CertificateFactory factory) {
        if (factory == null || cert.encodedLength() > CertificateTable.MAX_CERTIFICATE_SIZE) {
            return null;
        }
        try {
            Certificate c = factory.generateCertificate(new ByteArrayInputStream(cert.encoded()));
            return c instanceof X509Certificate ? (X509Certificate) c : null;
        } catch (AnalysisInterruptedException e) {
            throw e;
        } catch (CertificateException | RuntimeException e) {
            return null;
        }
    }

    /**
     * @return the first certificate whose subject key identifier equals ski
     */
    static Optional<AuthenticodeCertificate> findBySki(Iterable<AuthenticodeCertificate> bag, byte[] ski) {
        for (AuthenticodeCertificate c : bag) {
            byte[] other = c.subjectKeyIdentifier();
            if (other != null && java.util.Arrays.equals(other, ski)) {
                return Optional.of(c);
            }
        }
        return Optional.empty();
    }

    /**
     * @return the first certificate with the issuer name and serial number
     */
    static Optional<AuthenticodeCertificate> findByIssuerAndSerial(Iterable<AuthenticodeCertificate> bag,
                                                                   DerElement issuer, byte[] serial) {
        BigInteger serialValue = new BigInteger(serial);
        for (AuthenticodeCertificate c : bag) {
            if (c.issuerNameElement().equalEncoding(issuer)
                    && new BigInteger(c.serialBytes()).equals(serialValue)) {
                return Optional.of(c);
            }
        }
        return Optional.empty();
    }
}
