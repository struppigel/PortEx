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

import io.github.struppigel.parser.FileFormatException;
import io.github.struppigel.parser.IOUtil;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PhysicalLocation;
import io.github.struppigel.parser.optheader.DataDirEntry;
import io.github.struppigel.parser.optheader.DataDirectoryKey;
import io.github.struppigel.parser.sections.SectionLoader;
import io.github.struppigel.parser.sections.SpecialSection;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * The attribute certificate table of a PE file (data directory entry 4), which
 * holds the Authenticode signatures.
 * <p>
 * The address of the table is a file offset. The table is not mapped into
 * memory and usually lies at the end of the file, inside the overlay.
 * <p>
 * Parsing is bounded by the limits below and never throws for malformed data:
 * problems are reported as {@link CertificateIssue}s. Integrity checks are done
 * separately by {@link AuthenticodeVerifier}.
 * <p>
 * Example:
 * <pre>{@code
 * PEData data = PELoader.loadPE(file);
 * Optional<CertificateTable> table = data.loadCertificateTable();
 * table.flatMap(CertificateTable::getPrimarySignature)
 *      .flatMap(AuthenticodeSignature::getSigner)
 *      .flatMap(SignerInfo::getSignerCertificate)
 *      .ifPresent(c -> System.out.println(c.getSubjectName()));
 * }</pre>
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class CertificateTable implements SpecialSection {

    /** at most this many bytes of the table are read and parsed */
    public static final int MAX_TABLE_READ_SIZE = 4 * 1024 * 1024;
    /** at most this many WIN_CERTIFICATE entries are parsed */
    public static final int MAX_ENTRIES = 16;
    /** the maximum nesting depth of ASN.1 elements */
    public static final int MAX_DER_DEPTH = 64;
    /** the maximum number of ASN.1 elements in one encoded structure */
    public static final int MAX_DER_ELEMENTS = 100_000;
    /** at most this many certificates are parsed per signature */
    public static final int MAX_CERTIFICATES = 64;
    /** at most this many signers are parsed per signature */
    public static final int MAX_SIGNERS = 8;
    /** at most this many attributes are parsed per attribute set */
    public static final int MAX_ATTRIBUTES = 64;
    /** nested signatures deeper than this are not parsed */
    public static final int MAX_NESTING_DEPTH = 4;
    /** at most this many signatures, including nested ones, are parsed per table */
    public static final int MAX_SIGNATURES = 32;
    /** at most this many timestamps are parsed per signer */
    public static final int MAX_TIMESTAMPS = 8;
    /** larger certificates are not passed to the JDK certificate parser */
    public static final int MAX_CERTIFICATE_SIZE = 64 * 1024;
    /** object identifiers with more content bytes are reported as oversized */
    public static final int MAX_OID_LENGTH = 64;
    /** the maximum length of INTEGER values in bytes */
    public static final int MAX_INTEGER_LENGTH = 4096;
    /** serial numbers longer than this violate RFC 5280 */
    public static final int MAX_SERIAL_LENGTH = 20;
    /** unauthenticated attributes larger than this are reported */
    public static final int LARGE_UNAUTHENTICATED_ATTRIBUTE_SIZE = 64 * 1024;
    /** the maximum length of certificate chains */
    public static final int MAX_CHAIN_LENGTH = 16;
    /** at most this many issuer candidates are tried per certificate */
    public static final int MAX_ISSUER_CANDIDATES = 4;
    /** at most this many signature verifications are done per verification run */
    public static final int MAX_SIGNATURE_VERIFICATIONS = 512;
    /** RSA keys with larger moduli are not used for verification */
    public static final int MAX_RSA_MODULUS_BITS = 16384;
    /** RSA keys with larger public exponents are not used for verification */
    public static final int MAX_RSA_EXPONENT_BITS = 256;
    /** DSA keys with larger primes are not used for verification */
    public static final int MAX_DSA_P_BITS = 4096;
    /** the search range for a misplaced WIN_CERTIFICATE on each side of the declared offset */
    public static final int MISPLACED_SEARCH_WINDOW = 64 * 1024;
    /** the buffer size for hashing the image */
    public static final int HASH_BUFFER_SIZE = 1024 * 1024;
    /** at most this many issues are reported per table */
    public static final int MAX_ISSUES = 256;
    /** strings are cut after this many characters */
    public static final int MAX_STRING_LENGTH = 4096;
    /** at most this many attributes of a name are rendered */
    public static final int MAX_NAME_ATTRIBUTES = 64;

    private final long offset;
    private final long declaredSize;
    private final long readSize;
    private final long tableEntryOffset;
    private final boolean truncated;
    private final List<WinCertificate> entries;
    private final List<CertificateIssue> issues;
    private final List<PhysicalLocation> locations;

    CertificateTable(long offset, long declaredSize, long readSize, long tableEntryOffset, boolean truncated,
                     List<WinCertificate> entries, List<CertificateIssue> issues,
                     List<PhysicalLocation> locations) {
        this.offset = offset;
        this.declaredSize = declaredSize;
        this.readSize = readSize;
        this.tableEntryOffset = tableEntryOffset;
        this.truncated = truncated;
        this.entries = Collections.unmodifiableList(new ArrayList<>(entries));
        this.issues = Collections.unmodifiableList(new ArrayList<>(issues));
        this.locations = Collections.unmodifiableList(new ArrayList<>(locations));
    }

    /**
     * Creates the certificate table for the load information of the
     * {@link SectionLoader}.
     *
     * @param li the load information
     * @return the certificate table
     * @throws FileFormatException if the file can not be read
     */
    public static CertificateTable newInstance(SectionLoader.LoadInfo li) throws FileFormatException {
        try {
            return load(li.data);
        } catch (FileFormatException e) {
            throw e;
        } catch (IOException e) {
            throw new FileFormatException("unable to read the certificate table: " + e.getMessage());
        }
    }

    /**
     * Loads the certificate table of the PE file.
     *
     * @param data the PE data
     * @return the certificate table
     * @throws IOException           if the file can not be read
     * @throws IllegalStateException if the file has no certificate table entry
     */
    public static CertificateTable load(PEData data) throws IOException {
        java.util.Optional<DataDirEntry> entry = data.getOptionalHeader()
                .maybeGetDataDirEntry(DataDirectoryKey.CERTIFICATE_TABLE);
        if (!entry.isPresent()) {
            throw new IllegalStateException("the file has no certificate table entry");
        }
        return CertificateTableParser.parse(data, entry.get());
    }

    /**
     * @return the file offset of the table as declared in the data directory
     */
    @Override
    public long getOffset() {
        return offset;
    }

    /**
     * @return the size of the table as declared in the data directory
     */
    public long getDeclaredSize() {
        return declaredSize;
    }

    /**
     * @return the number of bytes that were read, at most the declared size,
     *         the bytes up to the end of the file and {@link #MAX_TABLE_READ_SIZE}
     */
    public long getReadSize() {
        return readSize;
    }

    /**
     * @return the file offset of the 8-byte data directory entry
     */
    public long getTableEntryOffset() {
        return tableEntryOffset;
    }

    /**
     * @return true iff the declared table exceeds the end of the file
     */
    public boolean isTruncated() {
        return truncated;
    }

    /**
     * @return true iff no WIN_CERTIFICATE could be read
     */
    @Override
    public boolean isEmpty() {
        return entries.isEmpty();
    }

    /**
     * @return the location of the table, clamped to the file; empty if the
     *         table starts outside of the file
     */
    @Override
    public List<PhysicalLocation> getPhysicalLocations() {
        return locations;
    }

    /**
     * @return the WIN_CERTIFICATE entries
     */
    public List<WinCertificate> getEntries() {
        return entries;
    }

    /**
     * @return the signature that Windows verifies: the signature of the first
     *         entry, if that entry has the type WIN_CERT_TYPE_PKCS_SIGNED_DATA
     *         and could be parsed
     */
    public Optional<AuthenticodeSignature> getPrimarySignature() {
        if (entries.isEmpty()) {
            return Optional.empty();
        }
        return entries.get(0).getSignature();
    }

    /**
     * @return the top level signature of each entry
     */
    public List<AuthenticodeSignature> getSignatures() {
        List<AuthenticodeSignature> result = new ArrayList<>();
        for (WinCertificate entry : entries) {
            entry.getSignature().ifPresent(result::add);
        }
        return Collections.unmodifiableList(result);
    }

    /**
     * @return all signatures including nested ones, in depth-first order
     */
    public List<AuthenticodeSignature> getAllSignatures() {
        List<AuthenticodeSignature> result = new ArrayList<>();
        for (AuthenticodeSignature signature : getSignatures()) {
            addDepthFirst(signature, result);
        }
        return Collections.unmodifiableList(result);
    }

    private static void addDepthFirst(AuthenticodeSignature signature, List<AuthenticodeSignature> result) {
        result.add(signature);
        for (AuthenticodeSignature nested : signature.getNestedSignatures()) {
            addDepthFirst(nested, result);
        }
    }

    /**
     * @return all problems of the table, its entries and signatures, in the
     *         order they were found
     */
    public List<CertificateIssue> getIssues() {
        return issues;
    }

    @Override
    public String getInfo() {
        StringBuilder sb = new StringBuilder();
        sb.append("Certificate Table at ").append(Hex.offset(offset)).append(", size ")
                .append(Hex.offset(declaredSize)).append(IOUtil.NL);
        for (WinCertificate entry : entries) {
            sb.append(entry).append(IOUtil.NL);
            entry.getSignature().ifPresent(s -> appendSignature(sb, s, "  "));
        }
        if (!issues.isEmpty()) {
            sb.append("Issues:").append(IOUtil.NL);
            for (CertificateIssue issue : issues) {
                sb.append("* ").append(issue.getDescription()).append(IOUtil.NL);
            }
        }
        return sb.toString();
    }

    private static void appendSignature(StringBuilder sb, AuthenticodeSignature s, String indent) {
        sb.append(indent).append(s).append(IOUtil.NL);
        for (AuthenticodeCertificate c : s.getCertificates()) {
            sb.append(indent).append("  ").append(c).append(IOUtil.NL);
        }
        for (SignerInfo signer : s.getSigners()) {
            for (Timestamp t : signer.getTimestamps()) {
                sb.append(indent).append("  ").append(t).append(IOUtil.NL);
            }
        }
        for (AuthenticodeSignature nested : s.getNestedSignatures()) {
            appendSignature(sb, nested, indent + "  ");
        }
    }

    @Override
    public String toString() {
        return getInfo();
    }
}
