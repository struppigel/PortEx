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

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import static io.github.struppigel.parser.sections.clr.ClrMutator.getLe;
import static io.github.struppigel.parser.sections.clr.ClrMutator.putLe;

/**
 * Writes one-property mutations of a known-good .NET executable for the runtime
 * acceptance experiment (see build-rt/run-acceptance.ps1). Not a test.
 * <p>
 * Usage: ClrAcceptanceFixtures base.exe outputDirectory [fatbase.exe]
 * <p>
 * The known-good executable must print OK and exit with 42, so that the runner
 * can tell "loaded and ran" from every other outcome. The optional second one has a method with a fat header.
 * Every mutation changes
 * exactly one property of the file. Controls: an unmodified copy (must be
 * accepted) and a copy with a destroyed metadata signature (must be rejected).
 */
public final class ClrAcceptanceFixtures {

    private static final class Mutation {
        final ClrMutator source;
        final String name;
        final String candidate;
        final String description;
        final Consumer<byte[]> change;

        Mutation(ClrMutator source, String name, String candidate, String description, Consumer<byte[]> change) {
            this.source = source;
            this.name = name;
            this.candidate = candidate;
            this.description = description;
            this.change = change;
        }
    }

    private final ClrMutator m;
    private final ClrMutator fat;
    private final List<Mutation> mutations = new ArrayList<>();

    private ClrAcceptanceFixtures(ClrMutator mutator, ClrMutator fatMutator) {
        this.m = mutator;
        this.fat = fatMutator;
    }

    private void add(String name, String candidate, String description, Consumer<byte[]> change) {
        mutations.add(new Mutation(m, name, candidate, description, change));
    }

    private void addFat(String name, String candidate, String description, Consumer<byte[]> change) {
        mutations.add(new Mutation(fat, name, candidate, description, change));
    }

    private void buildStreamsAndFatHeaders() throws IOException {
        add("mvid_null_control", "control for stream_name_unknown", "Module Mvid index set to 0, #GUID unchanged",
                b -> m.setTableField(b, CLRTableType.MODULE, 1, CLRTableKey.MODULE_MVID, 0));
        add("stream_name_unknown", "CLR_UNUSUAL_STREAM_NAME (NON_DEFAULT)",
                "#GUID renamed to #GUIX, the Mvid index is 0 so that nothing refers to the heap", b -> {
                    m.setTableField(b, CLRTableType.MODULE, 1, CLRTableKey.MODULE_MVID, 0);
                    b[(int) m.streamHeader("#GUID") + 8 + 4] = 'X';
                });
        add("stream_size_us_unaligned", "CLR_STREAM_SIZE_NOT_ALIGNED (WRONG)", "size of #US reduced by 1",
                b -> putLe(b, m.streamHeader("#US") + 4, m.streamSize("#US") - 1, 4));
        add("stream_size_strings_unaligned", "CLR_STREAM_SIZE_NOT_ALIGNED (WRONG)", "size of #Strings reduced by 1",
                b -> putLe(b, m.streamHeader("#Strings") + 4, m.streamSize("#Strings") - 1, 4));
        if (fat == null) {
            return;
        }
        final long header = fat.firstFatMethodHeaderOffset();
        addFat("control_fat_unmodified", "control", "unmodified copy with a fat method header, must be accepted", b -> { });
        for (int size : new int[]{2, 4, 5}) {
            addFat("fat_header_size_" + size, "CLR_INVALID_FAT_HEADER_SIZE (WRONG)",
                    "size of the fat method header of Main is " + size + " instead of 3",
                    b -> b[(int) header + 1] = (byte) ((b[(int) header + 1] & 0x0F) | (size << 4)));
        }
    }

    private void build() {
        final long flags = m.cliHeaderField(CLIHeaderKey.FLAGS);
        final long cb = m.cliHeaderField(CLIHeaderKey.CB);
        final long major = m.cliHeaderField(CLIHeaderKey.MAJOR_RUNTIME_VERSION);
        final long minor = m.cliHeaderField(CLIHeaderKey.MINOR_RUNTIME_VERSION);
        final long root = m.metadataRootField(MetadataRootKey.SIGNATURE);
        final long tables = m.tablesStream();

        add("control_unmodified", "control", "unmodified copy, must be accepted", b -> { });
        add("control_bad_bsjb", "control", "first byte of the BSJB signature destroyed, must be rejected",
                b -> b[(int) root] = 'X');

        add("clr_ilonly_cleared", "CLR_UNUSUAL_ILONLY_CLEARED (NON_DEFAULT)", "COMIMAGE_FLAGS_ILONLY cleared",
                b -> putLe(b, flags, getLe(b, flags, 4) & ~0x1L, 4));
        add("clr_flag_undefined_0x100", "CLR_UNDEFINED_FLAGS (RESERVED?)", "undefined CLI flag bit 0x100 set",
                b -> putLe(b, flags, getLe(b, flags, 4) | 0x100L, 4));
        add("clr_flag_native_entrypoint", "CLR_UNUSUAL_NATIVE_ENTRYPOINT (NON_DEFAULT)", "COMIMAGE_FLAGS_NATIVE_ENTRYPOINT set",
                b -> putLe(b, flags, getLe(b, flags, 4) | 0x10L, 4));
        add("clr_flag_trackdebugdata", "CLR_TRACKDEBUGDATA (RESERVED?)", "COMIMAGE_FLAGS_TRACKDEBUGDATA set",
                b -> putLe(b, flags, getLe(b, flags, 4) | 0x10000L, 4));
        add("clr_runtime_major_3", "CLR_RUNTIME_VERSION (NON_DEFAULT?)", "MajorRuntimeVersion 3 instead of 2",
                b -> putLe(b, major, 3, 2));
        add("clr_runtime_minor_9", "CLR_RUNTIME_VERSION (NON_DEFAULT?)", "MinorRuntimeVersion 9 instead of 5",
                b -> putLe(b, minor, 9, 2));
        add("clr_cb_0x50", "CLR_HEADER_SIZE (WRONG?)", "CLI header Cb 0x50 instead of 0x48",
                b -> putLe(b, cb, 0x50, 4));
        add("clr_cb_0x40", "CLR_HEADER_SIZE (WRONG?)", "CLI header Cb 0x40 instead of 0x48",
                b -> putLe(b, cb, 0x40, 4));
        add("clr_reserved_codemanager", "CLR_RESERVED_FIELD (RESERVED?)", "CodeManagerTable RVA and size set",
                b -> putRvaSize(b, m.cliHeaderField(CLIHeaderKey.CODE_MANAGER_TABLE)));
        add("clr_reserved_exportjumps", "CLR_RESERVED_FIELD (RESERVED?)", "ExportAddressTableJumps RVA and size set",
                b -> putRvaSize(b, m.cliHeaderField(CLIHeaderKey.EXPORT_ADDRESS_TABLE_JUMPS)));
        add("clr_reserved_managednative", "CLR_RESERVED_FIELD (RESERVED?)", "ManagedNativeHeader RVA and size set",
                b -> putRvaSize(b, m.cliHeaderField(CLIHeaderKey.MANAGED_NATIVE_HEADER)));

        add("md_root_major_2", "METADATA_ROOT_VERSION (NON_DEFAULT?)", "metadata root MajorVersion 2 instead of 1",
                b -> putLe(b, m.metadataRootField(MetadataRootKey.MAJOR_VERSION), 2, 2));
        add("md_root_minor_5", "METADATA_ROOT_VERSION (NON_DEFAULT?)", "metadata root MinorVersion 5 instead of 1",
                b -> putLe(b, m.metadataRootField(MetadataRootKey.MINOR_VERSION), 5, 2));
        add("md_root_reserved_1", "METADATA_ROOT_RESERVED (RESERVED?)", "metadata root Reserved is 1",
                b -> putLe(b, m.metadataRootField(MetadataRootKey.RESERVED), 1, 4));
        add("md_root_flags_1", "METADATA_ROOT_FLAGS (RESERVED?)", "metadata root Flags is 1",
                b -> putLe(b, m.metadataRootField(MetadataRootKey.FLAGS), 1, 2));
        add("md_version_string_v9", "METADATA_VERSION_STRING (NON_DEFAULT?)",
                "version string replaced by v9.9.99999 (same length), selects a runtime that is not installed",
                b -> {
                    byte[] text = "v9.9.99999".getBytes(StandardCharsets.US_ASCII);
                    System.arraycopy(text, 0, b, (int) root + 16, text.length);
                });

        add("tables_reserved0_1", "TABLES_RESERVED (RESERVED?)", "#~ first Reserved field is 1",
                b -> putLe(b, tables, 1, 4));
        add("tables_reserved1_0", "TABLES_RESERVED (RESERVED?)", "#~ second Reserved byte (offset 7, always 1) is 0",
                b -> b[(int) tables + 7] = 0);
        add("tables_major_3", "TABLES_SCHEMA_VERSION (WRONG?)", "#~ MajorVersion 3 instead of 2",
                b -> b[(int) tables + 4] = 3);
        add("tables_minor_1", "TABLES_SCHEMA_VERSION (WRONG?)", "#~ MinorVersion 1 instead of 0",
                b -> b[(int) tables + 5] = 1);
        add("tables_heapsizes_0x40", "TABLES_HEAP_SIZES (RESERVED?)", "undefined HeapSizes bit 0x40 set",
                b -> b[(int) tables + 6] |= 0x40);
        add("tables_heapsizes_0x80", "TABLES_HEAP_SIZES (RESERVED?)", "undefined HeapSizes bit 0x80 set",
                b -> b[(int) tables + 6] |= (byte) 0x80);
        add("tables_sorted_zero", "TABLES_SORTED (NON_DEFAULT?)", "Sorted bit vector cleared",
                b -> putLe(b, tables + 16, 0, 8));
        add("tables_sorted_all", "TABLES_SORTED (NON_DEFAULT?)", "Sorted bit vector all ones",
                b -> putLe(b, tables + 16, -1L, 8));

        String[] names = {"export", null, "resource", "exception", "certificate", null, "debug", "architecture",
                "globalptr", "tls", "loadconfig", "boundimport", null, "delayimport", null, "reserved"};
        for (int i = 0; i < names.length; i++) {
            if (names[i] == null) {
                continue;
            }
            final int index = i;
            add("datadir_" + names[i], "CLR_UNEXPECTED_DATA_DIR (WRONG?)",
                    "data directory " + index + " (" + names[i] + ") points to the CLI header, size 0x48",
                    b -> {
                        long clrDir = m.dataDirectoryEntry(14);
                        long rva = getLe(b, clrDir, 4);
                        long entry = m.dataDirectoryEntry(index);
                        putLe(b, entry, rva, 4);
                        putLe(b, entry + 4, 0x48, 4);
                    });
        }
    }

    private static void putRvaSize(byte[] bytes, long offset) {
        putLe(bytes, offset, 0x2000, 4);
        putLe(bytes, offset + 4, 8, 4);
    }

    private void write(Path out) throws IOException {
        Files.createDirectories(out);
        List<String> manifest = new ArrayList<>();
        manifest.add("file\tname\tcandidate\tdescription");
        int number = 0;
        for (Mutation mutation : mutations) {
            String file = String.format("%02d_%s.exe", number++, mutation.name);
            Files.write(out.resolve(file), mutation.source.mutatedBytes(mutation.change));
            manifest.add(file + "\t" + mutation.name + "\t" + mutation.candidate + "\t" + mutation.description);
        }
        Files.write(out.resolve("manifest.tsv"), manifest, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 2 || args.length > 3) {
            System.err.println("usage: ClrAcceptanceFixtures base.exe outputDirectory [fatbase.exe]");
            System.exit(2);
        }
        ClrMutator fatMutator = args.length == 3 ? new ClrMutator(new File(args[2])) : null;
        ClrAcceptanceFixtures fixtures = new ClrAcceptanceFixtures(new ClrMutator(new File(args[0])), fatMutator);
        fixtures.build();
        fixtures.buildStreamsAndFatHeaders();
        fixtures.write(new File(args[1]).toPath());
        System.out.println(fixtures.mutations.size() + " fixtures written to " + args[1]);
    }
}
