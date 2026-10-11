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
 * Malformed ASN.1 data or ASN.1 data that exceeds a parser limit.
 * <p>
 * Never leaves this package, the parsers turn it into a
 * {@link CertificateIssue}.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class DerException extends Exception {

    private static final long serialVersionUID = 1L;

    private final long fileOffset;
    private final boolean limitExceeded;

    /**
     * @param message    the description of the problem
     * @param fileOffset the file offset where the problem was found
     */
    DerException(String message, long fileOffset) {
        this(message, fileOffset, false);
    }

    /**
     * @param message       the description of the problem
     * @param fileOffset    the file offset where the problem was found
     * @param limitExceeded true iff a parser limit was hit instead of
     *                      malformed data
     */
    DerException(String message, long fileOffset, boolean limitExceeded) {
        super(message);
        this.fileOffset = fileOffset;
        this.limitExceeded = limitExceeded;
    }

    /**
     * @return the file offset where the problem was found
     */
    long getFileOffset() {
        return fileOffset;
    }

    /**
     * @return true iff a parser limit was hit
     */
    boolean isLimitExceeded() {
        return limitExceeded;
    }
}
