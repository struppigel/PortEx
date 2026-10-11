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
 * Object identifiers used by Authenticode, PKCS#7, RFC 3161 and X.509, and
 * their names.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class Oids {

    /* content types */
    static final String DATA = "1.2.840.113549.1.7.1";
    static final String SIGNED_DATA = "1.2.840.113549.1.7.2";
    static final String SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4";
    static final String SPC_PE_IMAGE_DATA = "1.3.6.1.4.1.311.2.1.15";
    static final String TST_INFO = "1.2.840.113549.1.9.16.1.4";

    /* signed attributes */
    static final String CONTENT_TYPE = "1.2.840.113549.1.9.3";
    static final String MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
    static final String SIGNING_TIME = "1.2.840.113549.1.9.5";
    static final String SPC_SP_OPUS_INFO = "1.3.6.1.4.1.311.2.1.12";
    static final String SPC_STATEMENT_TYPE = "1.3.6.1.4.1.311.2.1.11";
    static final String SMIME_CAPABILITIES = "1.2.840.113549.1.9.15";
    static final String SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12";
    static final String SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47";
    static final String CMS_ALGORITHM_PROTECTION = "1.2.840.113549.1.9.52";
    static final String SPC_RELAXED_PE_MARKER_CHECK = "1.3.6.1.4.1.311.2.6.1";
    static final String SPC_ENCRYPTED_DIGEST_RETRY_COUNT = "1.3.6.1.4.1.311.2.6.2";

    /* unauthenticated attributes */
    static final String COUNTER_SIGNATURE = "1.2.840.113549.1.9.6";
    static final String MS_RFC3161_TIMESTAMP = "1.3.6.1.4.1.311.3.3.1";
    static final String TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.2.14";
    static final String NESTED_SIGNATURE = "1.3.6.1.4.1.311.2.4.1";
    static final String INTENT_TO_SEAL = "1.3.6.1.4.1.311.2.4.2";
    static final String SEALING_SIGNATURE = "1.3.6.1.4.1.311.2.4.3";
    static final String SEALING_TIMESTAMP = "1.3.6.1.4.1.311.2.4.4";
    static final String PLATFORM_MANIFEST_BINARY_ID = "1.3.6.1.4.1.311.10.3.28";

    /* page hashes */
    static final String PAGE_HASHES_V1 = "1.3.6.1.4.1.311.2.3.1";
    static final String PAGE_HASHES_V2 = "1.3.6.1.4.1.311.2.3.2";
    /** class id of the SpcSerializedObject that holds the page hashes */
    static final String SPC_SERIALIZED_PAGE_HASHES_CLASS_ID = "a6b586d5b4a12466ae05a217da8e60d6";

    /* digests */
    static final String MD2 = "1.2.840.113549.2.2";
    static final String MD5 = "1.2.840.113549.2.5";
    static final String SHA1 = "1.3.14.3.2.26";
    static final String SHA224 = "2.16.840.1.101.3.4.2.4";
    static final String SHA256 = "2.16.840.1.101.3.4.2.1";
    static final String SHA384 = "2.16.840.1.101.3.4.2.2";
    static final String SHA512 = "2.16.840.1.101.3.4.2.3";

    /* public keys and signatures */
    static final String RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
    static final String MD2_WITH_RSA = "1.2.840.113549.1.1.2";
    static final String MD5_WITH_RSA = "1.2.840.113549.1.1.4";
    static final String SHA1_WITH_RSA = "1.2.840.113549.1.1.5";
    static final String MGF1 = "1.2.840.113549.1.1.8";
    static final String RSASSA_PSS = "1.2.840.113549.1.1.10";
    static final String SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
    static final String SHA384_WITH_RSA = "1.2.840.113549.1.1.12";
    static final String SHA512_WITH_RSA = "1.2.840.113549.1.1.13";
    static final String SHA224_WITH_RSA = "1.2.840.113549.1.1.14";
    static final String OIW_SHA1_WITH_RSA = "1.3.14.3.2.29";
    static final String OIW_MD5_WITH_RSA = "1.3.14.3.2.3";
    static final String OIW_DSA_WITH_SHA1 = "1.3.14.3.2.27";
    static final String EC_PUBLIC_KEY = "1.2.840.10045.2.1";
    static final String ECDSA_WITH_SHA1 = "1.2.840.10045.4.1";
    static final String ECDSA_WITH_SHA224 = "1.2.840.10045.4.3.1";
    static final String ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";
    static final String ECDSA_WITH_SHA384 = "1.2.840.10045.4.3.3";
    static final String ECDSA_WITH_SHA512 = "1.2.840.10045.4.3.4";
    static final String DSA = "1.2.840.10040.4.1";
    static final String DSA_WITH_SHA1 = "1.2.840.10040.4.3";
    static final String DSA_WITH_SHA224 = "2.16.840.1.101.3.4.3.1";
    static final String DSA_WITH_SHA256 = "2.16.840.1.101.3.4.3.2";
    static final String ED25519 = "1.3.101.112";
    static final String ED448 = "1.3.101.113";

    /* curves */
    static final String SECP256R1 = "1.2.840.10045.3.1.7";
    static final String SECP384R1 = "1.3.132.0.34";
    static final String SECP521R1 = "1.3.132.0.35";
    static final String SECP256K1 = "1.3.132.0.10";

    /* names and extensions */
    static final String COMMON_NAME = "2.5.4.3";
    static final String SUBJECT_KEY_IDENTIFIER = "2.5.29.14";

    private static final Map<String, String> NAMES;

    static {
        Map<String, String> m = new HashMap<>();
        m.put(DATA, "data");
        m.put(SIGNED_DATA, "signedData");
        m.put(SPC_INDIRECT_DATA, "SpcIndirectDataContent");
        m.put(SPC_PE_IMAGE_DATA, "SpcPeImageData");
        m.put(TST_INFO, "TSTInfo");
        m.put(CONTENT_TYPE, "contentType");
        m.put(MESSAGE_DIGEST, "messageDigest");
        m.put(SIGNING_TIME, "signingTime");
        m.put(SPC_SP_OPUS_INFO, "SpcSpOpusInfo");
        m.put(SPC_STATEMENT_TYPE, "SpcStatementType");
        m.put(SMIME_CAPABILITIES, "smimeCapabilities");
        m.put(SIGNING_CERTIFICATE, "signingCertificate");
        m.put(SIGNING_CERTIFICATE_V2, "signingCertificateV2");
        m.put(CMS_ALGORITHM_PROTECTION, "cmsAlgorithmProtection");
        m.put(SPC_RELAXED_PE_MARKER_CHECK, "SpcRelaxedPEMarkerCheck");
        m.put(SPC_ENCRYPTED_DIGEST_RETRY_COUNT, "SpcEncryptedDigestRetryCount");
        m.put(COUNTER_SIGNATURE, "counterSignature");
        m.put(MS_RFC3161_TIMESTAMP, "RFC 3161 timestamp (Microsoft)");
        m.put(TIMESTAMP_TOKEN, "timeStampToken");
        m.put(NESTED_SIGNATURE, "nested signature");
        m.put(INTENT_TO_SEAL, "intent to seal");
        m.put(SEALING_SIGNATURE, "sealing signature");
        m.put(SEALING_TIMESTAMP, "sealing timestamp");
        m.put(PLATFORM_MANIFEST_BINARY_ID, "platform manifest binary ID");
        m.put(PAGE_HASHES_V1, "page hashes v1 (SHA-1)");
        m.put(PAGE_HASHES_V2, "page hashes v2 (SHA-256)");
        m.put(MD2, "MD2");
        m.put(MD5, "MD5");
        m.put(SHA1, "SHA-1");
        m.put(SHA224, "SHA-224");
        m.put(SHA256, "SHA-256");
        m.put(SHA384, "SHA-384");
        m.put(SHA512, "SHA-512");
        m.put(RSA_ENCRYPTION, "rsaEncryption");
        m.put(MD2_WITH_RSA, "md2WithRSAEncryption");
        m.put(MD5_WITH_RSA, "md5WithRSAEncryption");
        m.put(SHA1_WITH_RSA, "sha1WithRSAEncryption");
        m.put(MGF1, "MGF1");
        m.put(RSASSA_PSS, "RSASSA-PSS");
        m.put(SHA256_WITH_RSA, "sha256WithRSAEncryption");
        m.put(SHA384_WITH_RSA, "sha384WithRSAEncryption");
        m.put(SHA512_WITH_RSA, "sha512WithRSAEncryption");
        m.put(SHA224_WITH_RSA, "sha224WithRSAEncryption");
        m.put(OIW_SHA1_WITH_RSA, "sha1WithRSA (OIW)");
        m.put(OIW_MD5_WITH_RSA, "md5WithRSA (OIW)");
        m.put(OIW_DSA_WITH_SHA1, "dsaWithSHA1 (OIW)");
        m.put(EC_PUBLIC_KEY, "ecPublicKey");
        m.put(ECDSA_WITH_SHA1, "ecdsa-with-SHA1");
        m.put(ECDSA_WITH_SHA224, "ecdsa-with-SHA224");
        m.put(ECDSA_WITH_SHA256, "ecdsa-with-SHA256");
        m.put(ECDSA_WITH_SHA384, "ecdsa-with-SHA384");
        m.put(ECDSA_WITH_SHA512, "ecdsa-with-SHA512");
        m.put(DSA, "DSA");
        m.put(DSA_WITH_SHA1, "dsa-with-SHA1");
        m.put(DSA_WITH_SHA224, "dsa-with-SHA224");
        m.put(DSA_WITH_SHA256, "dsa-with-SHA256");
        m.put(ED25519, "Ed25519");
        m.put(ED448, "Ed448");
        m.put(SECP256R1, "secp256r1");
        m.put(SECP384R1, "secp384r1");
        m.put(SECP521R1, "secp521r1");
        m.put(SECP256K1, "secp256k1");
        m.put(COMMON_NAME, "commonName");
        m.put(SUBJECT_KEY_IDENTIFIER, "subjectKeyIdentifier");
        NAMES = Collections.unmodifiableMap(m);
    }

    private Oids() {
    }

    /**
     * @param oid the OID in dotted notation
     * @return the name of the OID, empty if unknown
     */
    static Optional<String> name(String oid) {
        return Optional.ofNullable(NAMES.get(oid));
    }

    /**
     * @param oid the OID in dotted notation
     * @return the name of the OID or the OID itself if unknown
     */
    static String nameOrOid(String oid) {
        String name = NAMES.get(oid);
        return name == null ? oid : name;
    }
}
