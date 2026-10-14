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
package io.github.struppigel.parser.sections.clr;

import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.optheader.OptionalHeader.MagicNumber;
import io.github.struppigel.parser.sections.SectionLoader;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Writes mutated copies of a .NET fixture to a temporary directory and loads
 * them. The offsets of the structures are taken from the parsed original, so a
 * mutation changes exactly one property.
 */
public final class ClrMutator {

    private final byte[] original;
    private final Path dir;
    private final CLRSection clr;
    private final PEData fixtureData;

    public ClrMutator(File fixture) throws IOException {
        original = Files.readAllBytes(fixture.toPath());
        dir = Files.createTempDirectory("portex-clr-mutations");
        fixtureData = PELoader.loadPE(fixture);
        clr = new SectionLoader(fixtureData).loadCLRSection();
    }

    /** The mutated bytes of a copy of the fixture. */
    public byte[] mutatedBytes(Consumer<byte[]> mutation) {
        byte[] copy = Arrays.copyOf(original, original.length);
        mutation.accept(copy);
        return copy;
    }

    /** File offset of the first occurrence of the ASCII text in the fixture. */
    public long indexOf(String ascii) {
        byte[] needle = ascii.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        for (int i = 0; i <= original.length - needle.length; i++) {
            if (Arrays.equals(Arrays.copyOfRange(original, i, i + needle.length), needle)) {
                return i;
            }
        }
        throw new IllegalArgumentException(ascii);
    }

    /** A field of a row of a metadata table, rows start with 1. */
    public io.github.struppigel.parser.StandardField tableField(CLRTableType type, int row, CLRTableKey key) {
        CLRTable table = clr.getMetadataRoot().maybeGetOptimizedStream().get().getCLRTable(type).get();
        return table.getEntries().get(row - 1).get(key).get().toStandardField();
    }

    /** Number of rows of a metadata table, 0 if there is no such table. */
    public int rowCount(CLRTableType type) {
        scala.Option<CLRTable> table = clr.getMetadataRoot().maybeGetOptimizedStream().get().getCLRTable(type);
        return table.isDefined() ? table.get().getEntries().size() : 0;
    }

    /** Sets a field of a table row to the value, using the size of the field. */
    public void setTableField(byte[] bytes, CLRTableType type, int row, CLRTableKey key, long value) {
        io.github.struppigel.parser.StandardField field = tableField(type, row, key);
        putLe(bytes, field.getOffset(), value, (int) field.getSize());
    }

    /** File offset of the row count of a table in the #~ stream, the table has to be present. */
    public long rowCountField(int tableIndex) {
        long valid = getLe(original, tablesStreamValid(), 8);
        return tablesStreamFirstRowCount() + 4L * Long.bitCount(valid & ((1L << tableIndex) - 1));
    }

    /** File offset of the Characteristics field of the section that contains the CLI header. */
    public long cliHeaderSectionCharacteristics() throws IOException {
        long rva = getLe(original, dataDirectoryEntry(14), 4);
        return new SectionLoader(fixtureData).maybeGetSectionHeaderByRVA(rva).get()
                .getField(io.github.struppigel.parser.sections.SectionHeaderKey.CHARACTERISTICS).getOffset();
    }

    /** File offset of the header of the first method whose body has a fat header. */
    public long firstFatMethodHeaderOffset() throws IOException {
        CLRTable table = clr.getMetadataRoot().maybeGetOptimizedStream().get().getCLRTable(CLRTableType.METHODDEF).get();
        for (CLRTableEntry entry : table.getEntries()) {
            long rva = entry.get(CLRTableKey.METHOD_RVA).get().getValue();
            if (rva != 0) {
                long offset = fileOffset(rva);
                if ((original[(int) offset] & 3) == 3) {
                    return offset;
                }
            }
        }
        throw new IllegalStateException("no method with a fat header");
    }

    /** File offset of the RVA field of the first MethodDef row that has a method body. */
    public long firstMethodRvaField() {
        CLRTable table = clr.getMetadataRoot().maybeGetOptimizedStream().get().getCLRTable(CLRTableType.METHODDEF).get();
        for (CLRTableEntry entry : table.getEntries()) {
            CLRField rva = entry.get(CLRTableKey.METHOD_RVA).get();
            if (rva.getValue() != 0) {
                return rva.getOffset();
            }
        }
        throw new IllegalStateException("no method with a body");
    }

    /** RVA of the body of the first MethodDef row that has one. */
    public long firstMethodRva() {
        return getLe(original, firstMethodRvaField(), 4);
    }

    /** File offset of the RVA in the fixture. */
    public long fileOffset(long rva) throws IOException {
        return new SectionLoader(fixtureData).getFileOffset(rva);
    }

    /** File offset of the table a data directory points to. */
    public long dataDirectoryTarget(int index) throws IOException {
        return fileOffset(getLe(original, dataDirectoryEntry(index), 4));
    }

    /** File offset of a data directory entry, index 0 is the export table, 14 the CLR runtime header. */
    public long dataDirectoryEntry(int index) {
        boolean plus = fixtureData.getOptionalHeader().getMagicNumber() != MagicNumber.PE32;
        return fixtureData.getOptionalHeader().getOffset() + (plus ? 112 : 96) + 8L * index;
    }

    /** Applies the mutation to a copy of the fixture and loads the copy. */
    public PEData mutate(Consumer<byte[]> mutation) throws IOException {
        byte[] copy = Arrays.copyOf(original, original.length);
        mutation.accept(copy);
        File file = Files.createTempFile(dir, "mutated-", ".exe").toFile();
        Files.write(file.toPath(), copy);
        return PELoader.loadPE(file);
    }

    public int length() {
        return original.length;
    }

    /** File offset of a field of the CLI header. */
    public long cliHeaderField(CLIHeaderKey key) {
        return clr.getCliHeaderEntries().get(key).getOffset();
    }

    /** File offset of a field of the metadata root. */
    public long metadataRootField(MetadataRootKey key) {
        return clr.getMetadataRoot().getMetaDataEntries().get(key).getOffset();
    }

    /** File offset of the first byte of the #~ stream. */
    public long tablesStream() {
        return clr.getMetadataRoot().maybeGetOptimizedStream().get().getRawOffset();
    }

    /** File offset of the VALID bit vector in the #~ stream. */
    public long tablesStreamValid() {
        return tablesStream() + 8;
    }

    /** File offset of the first row count in the #~ stream. */
    public long tablesStreamFirstRowCount() {
        return tablesStream() + 24;
    }

    /** File offset of the first byte of the stream with the given name. */
    public long streamStart(String name) {
        MetadataRoot root = clr.getMetadataRoot();
        return root.getBSJBOffset() + root.maybeGetStreamHeaderByName(name).get().offset();
    }

    public long streamSize(String name) {
        return clr.getMetadataRoot().maybeGetStreamHeaderByName(name).get().size();
    }

    /** File offset of the stream header with the given name, the Offset field comes first, then the Size. */
    public long streamHeader(String name) {
        MetadataRoot root = clr.getMetadataRoot();
        long length = root.getMetaDataEntries().get(MetadataRootKey.LENGTH).getValue();
        long position = root.getBSJBOffset() + 16 + align4(length) + 4;
        for (StreamHeader header : root.getStreamHeaders()) {
            if (header.name().equals(name)) {
                return position;
            }
            position += 8 + align4(header.name().length() + 1);
        }
        throw new IllegalArgumentException(name);
    }

    private static long align4(long value) {
        return (value + 3) & ~3L;
    }

    /** Writes a little endian value of the given size in bytes. */
    public static void putLe(byte[] bytes, long offset, long value, int size) {
        for (int i = 0; i < size; i++) {
            bytes[(int) offset + i] = (byte) (value >>> (8 * i));
        }
    }

    public static long getLe(byte[] bytes, long offset, int size) {
        long value = 0;
        for (int i = size - 1; i >= 0; i--) {
            value = (value << 8) | (bytes[(int) offset + i] & 0xff);
        }
        return value;
    }

    public void delete() throws IOException {
        try (Stream<Path> files = Files.walk(dir)) {
            for (Path p : files.sorted(Comparator.reverseOrder()).collect(Collectors.toList())) {
                Files.deleteIfExists(p);
            }
        }
    }
}
