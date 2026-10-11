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
 * The result of one integrity check.
 * <p>
 * VALID means integrity only: no trust, revocation or expiry policy is
 * applied.
 *
 * @author Karsten Philipp Boris Hahn
 */
public enum VerificationStatus {
    /** the check passed */
    VALID,
    /** the check failed, the data was modified or the signature is wrong */
    INVALID,
    /**
     * the check could not be done, e.g. because of an unsupported algorithm,
     * a missing certificate or malformed data
     */
    UNVERIFIABLE,
    /** the check was not applicable, e.g. the issuer is not embedded */
    NOT_CHECKED
}
