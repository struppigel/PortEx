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

import io.github.struppigel.tools.anomalies.FieldOrStructureKey;

/**
 * Fields of the PKCS#7 signature that a {@link CertificateIssue} can concern.
 * Used as key of certificate anomalies.
 *
 * @author Karsten Philipp Boris Hahn
 */
public enum AuthenticodeFieldKey implements FieldOrStructureKey {
    /** content type of the SignedData or the contentType attribute */
    CONTENT_TYPE,
    /** a digest algorithm */
    DIGEST_ALGORITHM,
    /** a signature algorithm */
    SIGNATURE_ALGORITHM,
    /** the digest of the PE image in the SpcIndirectDataContent */
    IMAGE_DIGEST,
    /** the messageDigest signed attribute */
    MESSAGE_DIGEST,
    /** the signed (authenticated) attributes */
    SIGNED_ATTRIBUTES,
    /** the unauthenticated attributes */
    UNAUTHENTICATED_ATTRIBUTES,
    /** the signature value of a signer */
    SIGNER_SIGNATURE,
    /** the certificate of a signer */
    SIGNER_CERTIFICATE,
    /** the serial number of a certificate */
    CERTIFICATE_SERIAL_NUMBER,
    /** the public key of a certificate */
    CERTIFICATE_PUBLIC_KEY,
    /** the signature of a certificate */
    CERTIFICATE_SIGNATURE,
    /** a timestamp */
    TIMESTAMP,
    /** the page hashes */
    PAGE_HASHES,
    /** the padding of a WIN_CERTIFICATE */
    PADDING,
    /** the ASN.1 encoding */
    SIGNATURE_ENCODING
}
