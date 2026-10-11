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

import io.github.struppigel.parser.IOUtil;
import io.github.struppigel.parser.Interruption;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PhysicalLocation;
import io.github.struppigel.parser.StandardField;
import io.github.struppigel.parser.optheader.DataDirEntry;
import io.github.struppigel.parser.optheader.OptionalHeader;
import io.github.struppigel.parser.optheader.WindowsEntryKey;
import io.github.struppigel.parser.sections.SectionHeader;
import io.github.struppigel.parser.sections.SectionLoader;
import io.github.struppigel.parser.sections.cert.ParseContext.IssueSink;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Reads the certificate table: checks the data directory entry, the location
 * of the table, and each WIN_CERTIFICATE entry, and lets the
 * {@link SignedDataParser} parse the signatures.
 * <p>
 * All values are treated as unsigned 32-bit values and computed as longs.
 * Only {@link CertificateTable#MAX_TABLE_READ_SIZE} bytes are read, the
 * parsers never allocate memory based on other file values.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class CertificateTableParser {

    private static final String SPEC_NAME = "wincertificatespec";
    private static final IOUtil.SpecificationFormat FORMAT = new IOUtil.SpecificationFormat(0, 1, 2, 3);
    private static final long MAX_UINT32 = 0xffffffffL;
    private static volatile List<String[]> spec;

    private CertificateTableParser() {
    }

    private static List<String[]> spec() {
        List<String[]> s = spec;
        if (s == null) {
            try {
                s = Collections.unmodifiableList(IOUtil.readArray(SPEC_NAME));
            } catch (IOException e) {
                throw new UncheckedIOException("unable to read " + SPEC_NAME, e);
            }
            spec = s;
        }
        return s;
    }

    /**
     * @param data  the PE data
     * @param entry the certificate table data directory entry
     * @return the parsed table
     * @throws IOException if the file can not be read
     */
    static CertificateTable parse(PEData data, DataDirEntry entry) throws IOException {
        File file = data.getFile();
        long fileLength = file.length();
        long offset = entry.getVirtualAddress();
        long size = entry.getDirectorySize();
        ParseContext ctx = new ParseContext();
        IssueSink sink = ctx.sink();
        List<PhysicalLocation> dirLocation = Collections.singletonList(
                new PhysicalLocation(entry.getTableEntryOffset(), entry.getTableEntrySize()));

        if (offset % 8 != 0) {
            sink.add(CertificateIssueType.DIR_NOT_ALIGNED, "the certificate table offset " + Hex.offset(offset)
                    + " is not a multiple of 8", dirLocation, null, null);
        }
        if (size < WinCertificate.HEADER_SIZE) {
            sink.add(CertificateIssueType.DIR_TOO_SMALL, "the certificate table size " + Hex.offset(size)
                    + " is smaller than a WIN_CERTIFICATE header", dirLocation, null, null);
        }
        if (size > fileLength || offset + size > MAX_UINT32) {
            sink.add(CertificateIssueType.DIR_SIZE_EXCEEDS_FILE, "the certificate table size " + Hex.offset(size)
                    + " at offset " + Hex.offset(offset) + " exceeds the file size " + Hex.offset(fileLength)
                    + (offset + size > MAX_UINT32 ? " and the 32-bit address range" : ""), dirLocation, null, null);
        }
        if (offset >= fileLength) {
            sink.add(CertificateIssueType.TABLE_BEYOND_EOF, "the certificate table starts at " + Hex.offset(offset)
                    + ", outside of the file (" + Hex.offset(fileLength) + " bytes)", dirLocation, null, null);
            return new CertificateTable(offset, size, 0, entry.getTableEntryOffset(), true,
                    Collections.<WinCertificate>emptyList(), ctx.issues(), Collections.<PhysicalLocation>emptyList());
        }
        long available = fileLength - offset;
        boolean truncated = size > available;
        if (truncated) {
            sink.add(CertificateIssueType.TABLE_TRUNCATED, "the certificate table (" + Hex.offset(offset) + " to "
                    + Hex.offset(offset + size) + ") is cut off by the end of the file at " + Hex.offset(fileLength),
                    new PhysicalLocation(offset, available), null);
        }
        long tableAvailable = Math.min(size, available);
        long readSize = Math.min(tableAvailable, CertificateTable.MAX_TABLE_READ_SIZE);
        if (tableAvailable > CertificateTable.MAX_TABLE_READ_SIZE) {
            sink.add(CertificateIssueType.LIMIT_EXCEEDED, "only the first " + Hex.offset(readSize) + " of "
                    + Hex.offset(tableAvailable) + " bytes of the certificate table are parsed",
                    new PhysicalLocation(offset, tableAvailable), null);
        }
        List<PhysicalLocation> locations = tableAvailable > 0
                ? Collections.singletonList(new PhysicalLocation(offset, tableAvailable))
                : Collections.<PhysicalLocation>emptyList();

        List<WinCertificate> entries;
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            byte[] bytes = IOUtil.loadBytes(offset, (int) readSize, raf);
            EntryResult result = parseEntries(bytes, offset, size, ctx, sink);
            entries = result.entries;
            checkLocation(data, offset, size, tableAvailable, truncated, fileLength, sink);
            if (result.firstHeaderInvalid) {
                searchMisplaced(raf, offset, fileLength, sink);
            }
        }
        return new CertificateTable(offset, size, readSize, entry.getTableEntryOffset(), truncated, entries,
                ctx.issues(), locations);
    }

    private static final class EntryResult {
        private final List<WinCertificate> entries = new ArrayList<>();
        private boolean firstHeaderInvalid;
    }

    private static EntryResult parseEntries(byte[] bytes, long offset, long declaredSize, ParseContext ctx,
                                            IssueSink sink) {
        EntryResult result = new EntryResult();
        int readSize = bytes.length;
        long pos = 0;
        int index = 0;
        boolean stopped = false;
        if (readSize < WinCertificate.HEADER_SIZE) {
            result.firstHeaderInvalid = true;
        }
        while (pos + WinCertificate.HEADER_SIZE <= readSize) {
            Interruption.checkInterrupt();
            if (index >= CertificateTable.MAX_ENTRIES) {
                sink.add(CertificateIssueType.LIMIT_EXCEEDED, "more than " + CertificateTable.MAX_ENTRIES
                        + " WIN_CERTIFICATE entries, the rest is not parsed",
                        new PhysicalLocation(offset + pos, readSize - pos), null);
                stopped = true;
                break;
            }
            int p = (int) pos;
            if (index > 0 && !plausibleHeader(bytes, p, declaredSize - pos)) {
                sink.add(CertificateIssueType.TABLE_EXTRA_DATA, Hex.offset(readSize - pos)
                                + " bytes after the last WIN_CERTIFICATE do not form another entry",
                        new PhysicalLocation(offset + pos, readSize - pos), null);
                stopped = true;
                break;
            }
            long entryOffset = offset + pos;
            Map<WinCertificateKey, StandardField> fields = IOUtil.readHeaderEntriesForSpec(
                    WinCertificateKey.class, FORMAT, spec(), Arrays.copyOfRange(bytes, p, p + 8), entryOffset);
            long length = fields.get(WinCertificateKey.LENGTH).getValue();
            long revision = fields.get(WinCertificateKey.REVISION).getValue();
            long type = fields.get(WinCertificateKey.CERTIFICATE_TYPE).getValue();
            String who = "entry " + index;
            boolean headerInvalid = checkHeader(fields, revision, type, who, sink);

            boolean stop = false;
            boolean entryTruncated = false;
            long contentEnd;
            if (length < WinCertificate.HEADER_SIZE) {
                headerField(sink, CertificateIssueType.INVALID_LENGTH, who + ": dwLength " + Hex.offset(length)
                        + " is smaller than the WIN_CERTIFICATE header", fields.get(WinCertificateKey.LENGTH));
                contentEnd = pos + WinCertificate.HEADER_SIZE;
                stop = true;
                headerInvalid = true;
            } else {
                if (length > declaredSize - pos) {
                    headerField(sink, CertificateIssueType.INVALID_LENGTH, who + ": dwLength " + Hex.offset(length)
                            + " exceeds the remaining " + Hex.offset(declaredSize - pos)
                            + " bytes of the certificate table", fields.get(WinCertificateKey.LENGTH));
                    stop = true;
                    headerInvalid = true;
                }
                if (length > readSize - pos) {
                    entryTruncated = true;
                    stop = true;
                    contentEnd = readSize;
                } else {
                    contentEnd = pos + length;
                }
            }
            if (index == 0 && headerInvalid) {
                result.firstHeaderInvalid = true;
            }

            int contentStart = p + WinCertificate.HEADER_SIZE;
            int end = (int) contentEnd;
            AuthenticodeSignature signature = null;
            AuthenticodeCertificate x509 = null;
            int derEnd = -1;
            if ((type == WinCertType.PKCS_SIGNED_DATA.getValue() || type == WinCertType.X509.getValue())
                    && end > contentStart) {
                String what = who + (type == WinCertType.X509.getValue() ? " X.509 certificate" : " PKCS#7 signature");
                try {
                    DerDocument doc = DerReader.read(bytes, contentStart, end, offset);
                    derEnd = doc.root().endIndex();
                    if (doc.isBer()) {
                        sink.add(CertificateIssueType.BER_ENCODING, what + " uses BER instead of DER encoding, first at "
                                        + Hex.offset(doc.firstBerOffset()),
                                new PhysicalLocation(doc.firstBerOffset(), 1), AuthenticodeFieldKey.SIGNATURE_ENCODING);
                    }
                    if (type == WinCertType.PKCS_SIGNED_DATA.getValue()) {
                        signature = new SignedDataParser(ctx, doc.isBer()).parseAuthenticode(doc.root(), index, 0, 0);
                    } else {
                        x509 = CertificateParser.parse(doc.root(), sink);
                    }
                } catch (DerException e) {
                    sink.addDerException(what, e);
                }
            }
            if (derEnd >= 0 && !entryTruncated) {
                int trailing = end - derEnd;
                if (trailing > 7) {
                    sink.add(CertificateIssueType.DATA_AFTER_PKCS7, who + " has " + Hex.offset(trailing)
                                    + " bytes after the signature structure, data that is not covered by the signature"
                                    + " (CVE-2013-3900)",
                            new PhysicalLocation(offset + derEnd, trailing), AuthenticodeFieldKey.PADDING);
                } else if (trailing > 0 && !isZero(bytes, derEnd, end)) {
                    sink.add(CertificateIssueType.NONZERO_PADDING, who + " has non-zero padding after the signature",
                            new PhysicalLocation(offset + derEnd, trailing), AuthenticodeFieldKey.PADDING);
                }
            }
            long alignedEnd = align8(pos + Math.max(length, WinCertificate.HEADER_SIZE));
            if (!stop) {
                int alignStart = end;
                int alignEnd = (int) Math.min(alignedEnd, readSize);
                if (alignEnd > alignStart && !isZero(bytes, alignStart, alignEnd)) {
                    sink.add(CertificateIssueType.NONZERO_PADDING, who + " has non-zero alignment padding",
                            new PhysicalLocation(offset + alignStart, alignEnd - alignStart),
                            AuthenticodeFieldKey.PADDING);
                }
            }
            int paddingStart = derEnd >= 0 ? derEnd : end;
            int paddingEnd = stop ? end : (int) Math.min(alignedEnd, readSize);
            PhysicalLocation padding = paddingEnd > paddingStart
                    ? new PhysicalLocation(offset + paddingStart, paddingEnd - paddingStart) : null;
            result.entries.add(new WinCertificate(index, entryOffset, fields,
                    new PhysicalLocation(entryOffset, end - p),
                    new PhysicalLocation(offset + contentStart, end - contentStart), padding, entryTruncated,
                    Arrays.copyOfRange(bytes, contentStart, end), signature, x509));
            index++;
            if (stop) {
                stopped = true;
                break;
            }
            pos = alignedEnd;
        }
        if (!stopped && pos < readSize && !isZero(bytes, (int) pos, readSize)) {
            sink.add(CertificateIssueType.TABLE_EXTRA_DATA, Hex.offset(readSize - pos)
                            + " bytes after the last WIN_CERTIFICATE do not form another entry",
                    new PhysicalLocation(offset + pos, readSize - pos), null);
        }
        if (result.entries.size() > 1) {
            List<PhysicalLocation> locs = new ArrayList<>();
            for (WinCertificate e : result.entries) {
                locs.add(e.getPhysicalLocation());
            }
            sink.add(CertificateIssueType.MULTIPLE_ENTRIES, "the certificate table has " + result.entries.size()
                    + " WIN_CERTIFICATE entries, Windows only uses the first one", locs, null, null);
        }
        return result;
    }

    /**
     * Checks wRevision and wCertificateType.
     *
     * @return true iff a value is invalid
     */
    private static boolean checkHeader(Map<WinCertificateKey, StandardField> fields, long revision, long type,
                                       String who, IssueSink sink) {
        boolean invalid = false;
        StandardField revisionField = fields.get(WinCertificateKey.REVISION);
        if (revision == WinCertRevision.REVISION_1_0.getValue()) {
            headerField(sink, CertificateIssueType.DEPRECATED_REVISION, who
                    + ": wRevision 0x100 is the legacy WIN_CERT_REVISION_1_0", revisionField);
        } else if (revision != WinCertRevision.REVISION_2_0.getValue()) {
            headerField(sink, CertificateIssueType.INVALID_REVISION, who + ": wRevision " + Hex.offset(revision)
                    + " is invalid, it must be 0x200 (or 0x100)", revisionField);
            invalid = true;
        }
        StandardField typeField = fields.get(WinCertificateKey.CERTIFICATE_TYPE);
        if (type == WinCertType.RESERVED_1.getValue()) {
            headerField(sink, CertificateIssueType.RESERVED_TYPE, who
                    + ": wCertificateType 3 is the reserved WIN_CERT_TYPE_RESERVED_1", typeField);
        } else if (type == WinCertType.X509.getValue() || type == WinCertType.TS_STACK_SIGNED.getValue()) {
            headerField(sink, CertificateIssueType.UNSUPPORTED_TYPE, who + ": wCertificateType " + type + " ("
                    + WinCertType.forValue(type).get().name() + ") is not supported by Authenticode", typeField);
        } else if (type != WinCertType.PKCS_SIGNED_DATA.getValue()) {
            headerField(sink, CertificateIssueType.INVALID_TYPE, who + ": wCertificateType " + Hex.offset(type)
                    + " is invalid", typeField);
            invalid = true;
        }
        return invalid;
    }

    private static void headerField(IssueSink sink, CertificateIssueType type, String description,
                                    StandardField field) {
        sink.add(type, description, Collections.singletonList(
                new PhysicalLocation(field.getOffset(), field.getSize())), field, null);
    }

    private static boolean plausibleHeader(byte[] bytes, int p, long remaining) {
        long length = le(bytes, p, 4);
        long revision = le(bytes, p + 4, 2);
        long type = le(bytes, p + 6, 2);
        return length >= WinCertificate.HEADER_SIZE && length <= remaining
                && (revision == WinCertRevision.REVISION_1_0.getValue()
                || revision == WinCertRevision.REVISION_2_0.getValue())
                && type >= 1 && type <= 4;
    }

    /**
     * Checks the location of the table relative to headers, sections and the
     * end of the file.
     */
    private static void checkLocation(PEData data, long offset, long size, long tableAvailable,
                                      boolean truncated, long fileLength, IssueSink sink) {
        OptionalHeader opt = data.getOptionalHeader();
        long tableEnd = offset + tableAvailable;
        long sizeOfHeaders = opt.get(WindowsEntryKey.SIZE_OF_HEADERS);
        if (offset < sizeOfHeaders && tableAvailable > 0) {
            sink.add(CertificateIssueType.TABLE_IN_HEADERS, "the certificate table at " + Hex.offset(offset)
                            + " overlaps the headers, which end at " + Hex.offset(sizeOfHeaders),
                    new PhysicalLocation(offset, Math.min(sizeOfHeaders, tableEnd) - offset), null);
        }
        SectionLoader loader = new SectionLoader(data);
        boolean lowAlignment = opt.isLowAlignmentMode();
        for (SectionHeader header : data.getSectionTable().getSectionHeaders()) {
            long start = header.getAlignedPointerToRaw(lowAlignment);
            long readSize = loader.getReadSize(header);
            if (readSize > 0 && start < tableEnd && offset < start + readSize) {
                long overlapStart = Math.max(start, offset);
                long overlapEnd = Math.min(start + readSize, tableEnd);
                sink.add(CertificateIssueType.TABLE_IN_SECTION, "the certificate table overlaps section "
                                + header.getNumber() + " " + header.getName() + " (" + Hex.offset(start) + " to "
                                + Hex.offset(start + readSize) + ")",
                        new PhysicalLocation(overlapStart, overlapEnd - overlapStart), null);
            }
        }
        long declaredEnd = offset + size;
        if (!truncated && fileLength > declaredEnd) {
            sink.add(CertificateIssueType.TABLE_NOT_LAST, Hex.offset(fileLength - declaredEnd)
                            + " bytes follow the certificate table, which should be the last data of the file",
                    new PhysicalLocation(declaredEnd, fileLength - declaredEnd), null);
        }
    }

    /**
     * Searches a WIN_CERTIFICATE near the declared offset, which happens if the
     * pointer was not updated after the file was modified.
     */
    private static void searchMisplaced(RandomAccessFile raf, long offset, long fileLength, IssueSink sink)
            throws IOException {
        long windowStart = Math.max(0, offset - CertificateTable.MISPLACED_SEARCH_WINDOW);
        long windowEnd = Math.min(fileLength, offset + CertificateTable.MISPLACED_SEARCH_WINDOW + 16);
        if (windowEnd <= windowStart) {
            return;
        }
        byte[] window = IOUtil.loadBytes(windowStart, (int) (windowEnd - windowStart), raf);
        long best = -1;
        long bestLength = 0;
        for (int p = 0; p + 13 <= window.length; p++) {
            if ((p & 0xffff) == 0) {
                Interruption.checkInterrupt();
            }
            long candidate = windowStart + p;
            if (candidate == offset) {
                continue;
            }
            long revision = le(window, p + 4, 2);
            if (revision != WinCertRevision.REVISION_1_0.getValue()
                    && revision != WinCertRevision.REVISION_2_0.getValue()) {
                continue;
            }
            if (le(window, p + 6, 2) != WinCertType.PKCS_SIGNED_DATA.getValue()
                    || (window[p + 8] & 0xff) != 0x30) {
                continue;
            }
            long length = le(window, p, 4);
            if (length <= WinCertificate.HEADER_SIZE || length > fileLength - candidate) {
                continue;
            }
            int lengthByte = window[p + 9] & 0xff;
            long derLength;
            if (lengthByte == 0x82) {
                derLength = 4 + (((window[p + 10] & 0xff) << 8) | (window[p + 11] & 0xff));
            } else if (lengthByte == 0x83) {
                derLength = 5 + (((window[p + 10] & 0xff) << 16) | ((window[p + 11] & 0xff) << 8)
                        | (window[p + 12] & 0xff));
            } else {
                continue;
            }
            if (derLength + WinCertificate.HEADER_SIZE > length || length > derLength + WinCertificate.HEADER_SIZE + 7) {
                continue;
            }
            if (best < 0 || Math.abs(candidate - offset) < Math.abs(best - offset)) {
                best = candidate;
                bestLength = length;
            }
        }
        if (best >= 0) {
            sink.add(CertificateIssueType.TABLE_MISPLACED, "the certificate table pointer " + Hex.offset(offset)
                            + " is shifted by " + (best > offset ? "+" : "-") + Hex.offset(Math.abs(best - offset))
                            + ", a WIN_CERTIFICATE is at " + Hex.offset(best),
                    new PhysicalLocation(best, bestLength), null);
        }
    }

    private static long align8(long value) {
        return (value + 7) & ~7L;
    }

    private static boolean isZero(byte[] bytes, int from, int to) {
        for (int i = from; i < to; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        return true;
    }

    /** little endian unsigned value */
    private static long le(byte[] bytes, int p, int length) {
        long value = 0;
        for (int i = length - 1; i >= 0; i--) {
            value = (value << 8) | (bytes[p + i] & 0xff);
        }
        return value;
    }
}
