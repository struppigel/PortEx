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
/**
 * Parser for the attribute certificate table and its Authenticode signatures.
 * <p>
 * {@link io.github.struppigel.parser.sections.cert.CertificateTable} reads the
 * WIN_CERTIFICATE entries, the PKCS#7 SignedData, the embedded X.509
 * certificates, signers, timestamps and nested signatures.
 * {@link io.github.struppigel.parser.sections.cert.AuthenticodeVerifier}
 * checks their integrity: the image digest, the message digest and the
 * signatures of signers and certificates. It does not decide whether a signer
 * is trusted and does not check revocation.
 * <p>
 * The parser uses its own bounded ASN.1 reader and is meant for malformed and
 * manipulated files: sizes and counts are capped, nesting is bounded and
 * problems are reported as
 * {@link io.github.struppigel.parser.sections.cert.CertificateIssue}s instead
 * of exceptions.
 *
 * @author Karsten Philipp Boris Hahn
 */
package io.github.struppigel.parser.sections.cert;
