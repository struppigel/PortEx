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
import io.github.struppigel.parser.Interruption;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.IdentityHashMap;
import java.util.Map;

/**
 * Verifies signatures with the JDK, after checks that protect against
 * malicious keys and signature values.
 * <p>
 * ECDSA signature values are checked before the JDK sees them: r and s must
 * be in [1, n-1]. Java 15 to 18 accepted r = s = 0 for any message
 * (Psychic Signatures, CVE-2022-21449). Keys that are too large to verify in
 * reasonable time are rejected.
 * <p>
 * One instance is used for one verification run and counts the signature
 * verifications against {@link CertificateTable#MAX_SIGNATURE_VERIFICATIONS}.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class SignatureChecks {

    /** the outcome of one signature verification */
    static final class Outcome {
        final VerificationStatus status;
        final String reason;
        final CertificateIssueType issueType;

        private Outcome(VerificationStatus status, String reason, CertificateIssueType issueType) {
            this.status = status;
            this.reason = reason;
            this.issueType = issueType;
        }

        static Outcome valid() {
            return new Outcome(VerificationStatus.VALID, null, null);
        }

        static Outcome invalid(String reason) {
            return new Outcome(VerificationStatus.INVALID, reason, null);
        }
    }

    private final Map<AuthenticodeCertificate, Object> keys = new IdentityHashMap<>();
    private int verifications;

    /**
     * @param data      the signed data
     * @param signature the signature value
     * @param algorithm the signature algorithm, used for RSASSA-PSS parameters
     * @param jdkName   the JDK signature name, null if unsupported
     * @param signer    the certificate whose key is used
     * @return the outcome
     */
    Outcome verify(byte[] data, byte[] signature, AlgorithmId algorithm, String jdkName,
                   AuthenticodeCertificate signer) {
        Interruption.checkInterrupt();
        if (jdkName == null) {
            return new Outcome(VerificationStatus.UNVERIFIABLE, "the signature algorithm " + algorithm
                    + " is not supported", CertificateIssueType.UNSUPPORTED_ALGORITHM);
        }
        Object key = publicKey(signer);
        if (key instanceof Outcome) {
            return (Outcome) key;
        }
        PublicKey publicKey = (PublicKey) key;
        if (++verifications > CertificateTable.MAX_SIGNATURE_VERIFICATIONS) {
            return new Outcome(VerificationStatus.UNVERIFIABLE, "more than "
                    + CertificateTable.MAX_SIGNATURE_VERIFICATIONS + " signature verifications",
                    CertificateIssueType.LIMIT_EXCEEDED);
        }
        if (publicKey instanceof ECPublicKey) {
            Outcome ecdsa = checkEcdsaValue(signature, ((ECPublicKey) publicKey).getParams().getOrder());
            if (ecdsa != null) {
                return ecdsa;
            }
        }
        try {
            Signature verifier = Signature.getInstance(jdkName);
            if ("RSASSA-PSS".equals(jdkName)) {
                verifier.setParameter(pssParameters(algorithm));
            }
            verifier.initVerify(publicKey);
            verifier.update(data);
            if (verifier.verify(signature) || verifiesBareDigest(data, signature, jdkName, publicKey)) {
                return Outcome.valid();
            }
            return new Outcome(VerificationStatus.INVALID, "the signature does not match", null);
        } catch (SignatureException e) {
            return new Outcome(VerificationStatus.INVALID, "the signature is malformed: " + e.getMessage(), null);
        } catch (DerException e) {
            return new Outcome(VerificationStatus.UNVERIFIABLE, "malformed RSASSA-PSS parameters: "
                    + e.getMessage(), null);
        } catch (GeneralSecurityException e) {
            return new Outcome(VerificationStatus.UNVERIFIABLE, "the JDK can not verify " + jdkName + ": "
                    + e.getMessage(), CertificateIssueType.UNSUPPORTED_ALGORITHM);
        } catch (AnalysisInterruptedException e) {
            throw e;
        } catch (RuntimeException e) {
            return new Outcome(VerificationStatus.UNVERIFIABLE, "the JDK failed to verify " + jdkName + ": " + e,
                    null);
        }
    }

    /**
     * Old VeriSign and Symantec timestamp countersignatures sign the bare
     * digest with PKCS#1 v1.5 padding, without the DigestInfo structure.
     * Windows accepts them, so they are accepted here too.
     *
     * @return true iff the RSA signature is valid for the bare digest of data
     */
    private static boolean verifiesBareDigest(byte[] data, byte[] signature, String jdkName, PublicKey key)
            throws GeneralSecurityException {
        if (!(key instanceof RSAPublicKey) || !jdkName.endsWith("withRSA")) {
            return false;
        }
        String digest = jdkName.substring(0, jdkName.length() - "withRSA".length());
        digest = digest.startsWith("SHA") ? "SHA-" + digest.substring(3) : digest;
        byte[] hash = MessageDigest.getInstance(digest).digest(data);
        Signature raw = Signature.getInstance("NONEwithRSA");
        raw.initVerify(key);
        raw.update(hash);
        return raw.verify(signature);
    }

    /**
     * @return the public key, or an Outcome that explains why there is none
     */
    private Object publicKey(AuthenticodeCertificate certificate) {
        Object cached = keys.get(certificate);
        if (cached == null) {
            cached = createKey(certificate);
            keys.put(certificate, cached);
        }
        return cached;
    }

    private static Object createKey(AuthenticodeCertificate certificate) {
        if (certificate.hasExplicitCurveParameters()) {
            return new Outcome(VerificationStatus.UNVERIFIABLE, "the key of " + certificate.displayName()
                    + " uses explicit EC parameters", null);
        }
        String algorithm = Algorithms.keyAlgorithm(certificate.getPublicKeyAlgorithm().getOid()).orElse(null);
        if (algorithm == null) {
            return new Outcome(VerificationStatus.UNVERIFIABLE, "the key algorithm "
                    + certificate.getPublicKeyAlgorithm() + " of " + certificate.displayName()
                    + " is not supported", CertificateIssueType.UNSUPPORTED_ALGORITHM);
        }
        PublicKey key;
        try {
            key = KeyFactory.getInstance(algorithm).generatePublic(
                    new X509EncodedKeySpec(certificate.subjectPublicKeyInfo().encoded()));
        } catch (GeneralSecurityException e) {
            return new Outcome(VerificationStatus.UNVERIFIABLE, "the key of " + certificate.displayName()
                    + " can not be read: " + e.getMessage(), null);
        } catch (AnalysisInterruptedException e) {
            throw e;
        } catch (RuntimeException e) {
            return new Outcome(VerificationStatus.UNVERIFIABLE, "the key of " + certificate.displayName()
                    + " can not be read: " + e, null);
        }
        if (key instanceof RSAPublicKey) {
            RSAPublicKey rsa = (RSAPublicKey) key;
            if (rsa.getModulus().bitLength() > CertificateTable.MAX_RSA_MODULUS_BITS
                    || rsa.getPublicExponent().bitLength() > CertificateTable.MAX_RSA_EXPONENT_BITS) {
                return new Outcome(VerificationStatus.UNVERIFIABLE, "the RSA key of " + certificate.displayName()
                        + " is too large to verify", CertificateIssueType.LIMIT_EXCEEDED);
            }
        } else if (key instanceof DSAPublicKey) {
            DSAPublicKey dsa = (DSAPublicKey) key;
            if (dsa.getParams() == null || dsa.getParams().getP().bitLength() > CertificateTable.MAX_DSA_P_BITS) {
                return new Outcome(VerificationStatus.UNVERIFIABLE, "the DSA key of " + certificate.displayName()
                        + " is too large to verify", CertificateIssueType.LIMIT_EXCEEDED);
            }
        }
        return key;
    }

    /**
     * Checks that the ECDSA signature value is a SEQUENCE of r and s with
     * 0 &lt; r, s &lt; n.
     *
     * @return null if the value is acceptable, otherwise the INVALID outcome
     */
    static Outcome checkEcdsaValue(byte[] signature, BigInteger order) {
        BigInteger r;
        BigInteger s;
        try {
            DerElement sequence = DerReader.read(signature, 0, signature.length, 0).root().expectSequence();
            if (sequence.childCount() != 2) {
                throw new DerException("ECDSA signature value must have two elements", 0);
            }
            r = sequence.child(0).asInteger(CertificateTable.MAX_INTEGER_LENGTH);
            s = sequence.child(1).asInteger(CertificateTable.MAX_INTEGER_LENGTH);
        } catch (DerException e) {
            return new Outcome(VerificationStatus.INVALID, "the ECDSA signature value is malformed: "
                    + e.getMessage(), null);
        }
        if (r.signum() <= 0 || s.signum() <= 0 || r.compareTo(order) >= 0 || s.compareTo(order) >= 0) {
            return new Outcome(VerificationStatus.INVALID, "the ECDSA signature value has r or s outside of"
                    + " [1, n-1] (Psychic Signatures, CVE-2022-21449)", CertificateIssueType.INVALID_ECDSA_VALUE);
        }
        return null;
    }

    /**
     * RSASSA-PSS-params ::= SEQUENCE { hashAlgorithm [0], maskGenAlgorithm [1],
     * saltLength [2], trailerField [3] }, all with defaults.
     */
    private static PSSParameterSpec pssParameters(AlgorithmId algorithm) throws DerException {
        String hash = "SHA-1";
        String mgfHash = "SHA-1";
        int salt = 20;
        DerElement params = algorithm.parameters();
        if (params != null && params.isSequence()) {
            for (DerElement p : params.children()) {
                if (p.isContext(0)) {
                    hash = digestName(p.explicitContent().expectSequence().child(0).asOid());
                } else if (p.isContext(1)) {
                    DerElement mgf = p.explicitContent().expectSequence();
                    if (!Oids.MGF1.equals(mgf.child(0).asOid())) {
                        throw new DerException("unsupported mask generation function", mgf.fileOffset());
                    }
                    mgfHash = digestName(mgf.child(1).expectSequence().child(0).asOid());
                } else if (p.isContext(2)) {
                    salt = p.explicitContent().asSmallInteger();
                } else if (p.isContext(3) && p.explicitContent().asSmallInteger() != 1) {
                    throw new DerException("unsupported trailer field", p.fileOffset());
                }
            }
        }
        return new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(mgfHash), salt, 1);
    }

    private static String digestName(String oid) throws DerException {
        return Algorithms.digestJdkName(oid).orElseThrow(() ->
                new DerException("unsupported digest " + oid + " in RSASSA-PSS parameters", 0));
    }
}
