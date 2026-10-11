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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Maps algorithm OIDs to the names that the JDK providers use.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class Algorithms {

    /** digest OID to JDK MessageDigest name */
    private static final Map<String, String> DIGESTS;
    /** combined signature OID to the digest OID it uses */
    private static final Map<String, String> SIGNATURE_DIGESTS;
    /** combined signature OID to the key algorithm it uses */
    private static final Map<String, String> SIGNATURE_KEYS;

    static {
        Map<String, String> d = new HashMap<>();
        d.put(Oids.MD2, "MD2");
        d.put(Oids.MD5, "MD5");
        d.put(Oids.SHA1, "SHA-1");
        d.put(Oids.SHA224, "SHA-224");
        d.put(Oids.SHA256, "SHA-256");
        d.put(Oids.SHA384, "SHA-384");
        d.put(Oids.SHA512, "SHA-512");
        DIGESTS = Collections.unmodifiableMap(d);

        Map<String, String> sd = new HashMap<>();
        Map<String, String> sk = new HashMap<>();
        put(sd, sk, Oids.MD2_WITH_RSA, Oids.MD2, "RSA");
        put(sd, sk, Oids.MD5_WITH_RSA, Oids.MD5, "RSA");
        put(sd, sk, Oids.SHA1_WITH_RSA, Oids.SHA1, "RSA");
        put(sd, sk, Oids.SHA224_WITH_RSA, Oids.SHA224, "RSA");
        put(sd, sk, Oids.SHA256_WITH_RSA, Oids.SHA256, "RSA");
        put(sd, sk, Oids.SHA384_WITH_RSA, Oids.SHA384, "RSA");
        put(sd, sk, Oids.SHA512_WITH_RSA, Oids.SHA512, "RSA");
        put(sd, sk, Oids.OIW_SHA1_WITH_RSA, Oids.SHA1, "RSA");
        put(sd, sk, Oids.OIW_MD5_WITH_RSA, Oids.MD5, "RSA");
        put(sd, sk, Oids.ECDSA_WITH_SHA1, Oids.SHA1, "EC");
        put(sd, sk, Oids.ECDSA_WITH_SHA224, Oids.SHA224, "EC");
        put(sd, sk, Oids.ECDSA_WITH_SHA256, Oids.SHA256, "EC");
        put(sd, sk, Oids.ECDSA_WITH_SHA384, Oids.SHA384, "EC");
        put(sd, sk, Oids.ECDSA_WITH_SHA512, Oids.SHA512, "EC");
        put(sd, sk, Oids.DSA_WITH_SHA1, Oids.SHA1, "DSA");
        put(sd, sk, Oids.OIW_DSA_WITH_SHA1, Oids.SHA1, "DSA");
        put(sd, sk, Oids.DSA_WITH_SHA224, Oids.SHA224, "DSA");
        put(sd, sk, Oids.DSA_WITH_SHA256, Oids.SHA256, "DSA");
        SIGNATURE_DIGESTS = Collections.unmodifiableMap(sd);
        SIGNATURE_KEYS = Collections.unmodifiableMap(sk);
    }

    private static void put(Map<String, String> sd, Map<String, String> sk, String sigOid,
                            String digestOid, String keyAlgorithm) {
        sd.put(sigOid, digestOid);
        sk.put(sigOid, keyAlgorithm);
    }

    private Algorithms() {
    }

    /**
     * @param digestOid the digest OID
     * @return the JDK name of the digest, e.g. "SHA-256", empty if unknown
     */
    static Optional<String> digestJdkName(String digestOid) {
        return Optional.ofNullable(DIGESTS.get(digestOid));
    }

    /**
     * @param oid a digest or signature OID
     * @return true iff the OID is MD2, MD5 or a signature that uses them
     */
    static boolean isWeak(String oid) {
        String digest = SIGNATURE_DIGESTS.containsKey(oid) ? SIGNATURE_DIGESTS.get(oid) : oid;
        return Oids.MD2.equals(digest) || Oids.MD5.equals(digest);
    }

    /**
     * @param oid a digest or signature OID
     * @return true iff the OID is SHA-1 or a signature that uses SHA-1
     */
    static boolean isSha1(String oid) {
        String digest = SIGNATURE_DIGESTS.containsKey(oid) ? SIGNATURE_DIGESTS.get(oid) : oid;
        return Oids.SHA1.equals(digest);
    }

    /**
     * @param oid any OID
     * @return true iff it is a known digest OID
     */
    static boolean isDigest(String oid) {
        return DIGESTS.containsKey(oid);
    }

    /**
     * @param signatureOid a combined signature OID, e.g. sha256WithRSAEncryption
     * @return the digest OID that the signature algorithm implies, empty for
     *         plain key algorithms like rsaEncryption
     */
    static Optional<String> impliedDigest(String signatureOid) {
        return Optional.ofNullable(SIGNATURE_DIGESTS.get(signatureOid));
    }

    /**
     * @param oid a signature or public key OID
     * @return true iff it is a known signature or key algorithm
     */
    static boolean isSignatureAlgorithm(String oid) {
        return SIGNATURE_KEYS.containsKey(oid) || keyAlgorithm(oid).isPresent();
    }

    /**
     * @param keyOid the OID of a SubjectPublicKeyInfo algorithm
     * @return the JDK KeyFactory name, empty if unsupported
     */
    static Optional<String> keyAlgorithm(String keyOid) {
        switch (keyOid) {
            case Oids.RSA_ENCRYPTION:
                return Optional.of("RSA");
            case Oids.RSASSA_PSS:
                return Optional.of("RSASSA-PSS");
            case Oids.EC_PUBLIC_KEY:
                return Optional.of("EC");
            case Oids.DSA:
                return Optional.of("DSA");
            default:
                return Optional.empty();
        }
    }

    /**
     * Resolves the JDK Signature name for a signature algorithm and a digest.
     * Plain key algorithms (rsaEncryption, ecPublicKey, DSA) are combined
     * with the digest, combined OIDs bring their own digest. RSASSA-PSS is
     * returned as "RSASSA-PSS", its parameters are applied separately.
     *
     * @param signatureOid the signature algorithm OID
     * @param digestOid    the digest OID that is used with plain key algorithms
     * @return the JDK name, e.g. "SHA256withRSA", empty if unsupported
     */
    static Optional<String> signatureJdkName(String signatureOid, String digestOid) {
        if (Oids.RSASSA_PSS.equals(signatureOid)) {
            return Optional.of("RSASSA-PSS");
        }
        String digest = SIGNATURE_DIGESTS.containsKey(signatureOid)
                ? SIGNATURE_DIGESTS.get(signatureOid) : digestOid;
        String key = SIGNATURE_KEYS.containsKey(signatureOid)
                ? SIGNATURE_KEYS.get(signatureOid) : keyAlgorithm(signatureOid).orElse(null);
        if (key == null || digest == null || !DIGESTS.containsKey(digest)) {
            return Optional.empty();
        }
        String digestPart = DIGESTS.get(digest).replace("-", "");
        String keyPart = "EC".equals(key) ? "ECDSA" : key;
        return Optional.of(digestPart + "with" + keyPart);
    }
}
