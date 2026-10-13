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
 * The kinds of problems that the certificate table parser and the Authenticode
 * verifier report.
 * <p>
 * The anomaly scanner maps every type to an anomaly subtype with the same
 * name and the prefix CERT_, except {@link #TABLE_BEYOND_EOF}, which is
 * reported as INVALID_DATA_DIR, and {@link #LIMIT_EXCEEDED}, which is
 * reported as EXHAUSTIVE_DATA.
 *
 * @author Karsten Philipp Boris Hahn
 */
public enum CertificateIssueType {

    /* data directory entry */

    /** the certificate table offset is not a multiple of 8 */
    DIR_NOT_ALIGNED("certificate table offset is not 8-byte aligned"),
    /** the declared size is larger than the file or the end overflows 32 bits */
    DIR_SIZE_EXCEEDS_FILE("certificate table size exceeds the file"),
    /** the declared size is smaller than one WIN_CERTIFICATE header */
    DIR_TOO_SMALL("certificate table size is smaller than 8 bytes"),
    /** the table starts at or after the end of the file */
    TABLE_BEYOND_EOF("certificate table starts outside of the file"),

    /* WIN_CERTIFICATE header */

    /** dwLength is smaller than 8 or larger than the table */
    INVALID_LENGTH("invalid WIN_CERTIFICATE length"),
    /** wRevision is neither 0x0100 nor 0x0200 */
    INVALID_REVISION("invalid WIN_CERTIFICATE revision"),
    /** wRevision is the legacy 0x0100 */
    DEPRECATED_REVISION("deprecated WIN_CERTIFICATE revision 1.0"),
    /** wCertificateType is WIN_CERT_TYPE_RESERVED_1 */
    RESERVED_TYPE("reserved WIN_CERTIFICATE type"),
    /** wCertificateType is X509 or TS_STACK_SIGNED, which Windows does not support */
    UNSUPPORTED_TYPE("WIN_CERTIFICATE type is not supported by Authenticode"),
    /** wCertificateType is not defined */
    INVALID_TYPE("invalid WIN_CERTIFICATE type"),

    /* structure */

    /** the table is cut off by the end of the file */
    TABLE_TRUNCATED("certificate table is truncated by the end of the file"),
    /** the table overlaps the headers */
    TABLE_IN_HEADERS("certificate table overlaps the headers"),
    /** the table overlaps the raw data of a section */
    TABLE_IN_SECTION("certificate table overlaps a section"),
    /** data follows the table */
    TABLE_NOT_LAST("data follows the certificate table"),
    /** the directory points next to a WIN_CERTIFICATE that exists nearby */
    TABLE_MISPLACED("certificate table pointer is shifted"),
    /** the table has more than one WIN_CERTIFICATE */
    MULTIPLE_ENTRIES("certificate table has several entries"),
    /** the table is larger than its entries */
    TABLE_EXTRA_DATA("certificate table has data after its entries"),
    /** a WIN_CERTIFICATE has data after the PKCS#7 structure (CVE-2013-3900) */
    DATA_AFTER_PKCS7("data after the PKCS#7 signature"),
    /** the PKCS#7 structure has an element that its format does not define */
    EXTRA_SIGNATURE_ELEMENT("element that the signature format does not define"),
    /** the PKCS#7 structure can not be parsed */
    MALFORMED_PKCS7("malformed PKCS#7 signature"),
    /** nested signatures are nested deeply or occur often */
    UNUSUAL_NESTING("unusual signature nesting"),
    /** a SignedData has not exactly one SignerInfo */
    UNUSUAL_SIGNER_COUNT("unusual number of signers"),
    /** the certificate of a signer is not embedded */
    MISSING_SIGNER_CERTIFICATE("signer certificate is missing"),
    /** an unauthenticated attribute is larger than 64 KiB */
    LARGE_UNAUTH_ATTRIBUTE("large unauthenticated attribute"),
    /** an embedded certificate is unrelated to the signers and other certificates */
    ISOLATED_CERTIFICATE("isolated certificate"),
    /** a parser limit was hit, the rest was not parsed */
    LIMIT_EXCEEDED("parser limit exceeded"),

    /* fields of the signature */

    /** the computed image digest differs from the signed one */
    IMAGE_DIGEST_MISMATCH("image digest mismatch"),
    /** the messageDigest attribute differs from the digest of the content */
    MESSAGE_DIGEST_MISMATCH("message digest mismatch"),
    /** the signature of a signer is invalid */
    INVALID_SIGNER_SIGNATURE("invalid signer signature"),
    /** the signature of a certificate is invalid */
    INVALID_CERTIFICATE_SIGNATURE("invalid certificate signature"),
    /** a timestamp does not match or its signature is invalid */
    INVALID_TIMESTAMP("invalid timestamp"),
    /** an EC key uses explicit curve parameters (CurveBall, CVE-2020-0601) */
    EXPLICIT_EC_PARAMETERS("EC key with explicit curve parameters"),
    /** an ECDSA signature value r or s is zero or too large (CVE-2022-21449) */
    INVALID_ECDSA_VALUE("invalid ECDSA signature value"),
    /** the content type is not the expected one */
    WRONG_CONTENT_TYPE("wrong content type"),
    /** the digest algorithms of the signature contradict each other */
    DIGEST_ALGORITHM_MISMATCH("digest algorithm mismatch"),
    /** a mandatory signed attribute is missing */
    MISSING_SIGNED_ATTRIBUTE("missing signed attribute"),
    /** the padding of a WIN_CERTIFICATE is not zero */
    NONZERO_PADDING("non-zero padding"),
    /** a serial number is longer than 20 bytes */
    OVERSIZED_SERIAL("oversized serial number"),
    /** an object identifier is too long */
    OVERSIZED_OID("oversized object identifier"),
    /** the page hashes are malformed */
    INVALID_PAGE_HASHES("invalid page hashes"),
    /** MD2 or MD5 is used */
    WEAK_DIGEST("weak digest algorithm"),
    /** SHA-1 is used */
    SHA1_DIGEST("SHA-1 digest algorithm"),
    /** BER instead of DER encoding is used */
    BER_ENCODING("BER encoding"),
    /** the signer certificate is self-signed */
    SELF_SIGNED_SIGNER("self-signed signer certificate"),
    /** the signer certificate was not valid at the signing time */
    SIGNER_NOT_VALID_AT_SIGNING_TIME("signer certificate not valid at signing time"),
    /** an unauthenticated attribute has an unknown type */
    UNKNOWN_UNAUTH_ATTRIBUTE("unknown unauthenticated attribute"),
    /** an unauthenticated attribute has a type that Authenticode does not use there */
    UNEXPECTED_UNAUTH_ATTRIBUTE("unexpected unauthenticated attribute"),
    /** the SpcRelaxedPEMarkerCheck attribute is present */
    RELAXED_PE_MARKER_CHECK("relaxed PE marker check"),
    /** an algorithm is not supported */
    UNSUPPORTED_ALGORITHM("unsupported algorithm");

    private final String description;

    CertificateIssueType(String description) {
        this.description = description;
    }

    /**
     * @return a short description of the issue type
     */
    public String getDescription() {
        return description;
    }
}
