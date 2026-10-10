package io.github.struppigel.parser.sections.clr;

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.Mapping;
import io.github.struppigel.parser.Mapping$;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.PhysRange;
import io.github.struppigel.parser.VirtRange;
import io.github.struppigel.parser.sections.SectionLoader;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class CLRReadPathTest {

    @Test
    public void chunkedAndUnchunkedClrTablesDecodeIdentically() throws IOException {
        boolean originalUseChunks = Mapping$.MODULE$.useChunks();
        try {
            for (String fixture : Arrays.asList("HelloWorld.exe", "HelloWorld.TablesStream.ExtraData.exe")) {
                File file = fixtureFile(fixture);

                Mapping$.MODULE$.useChunks_$eq(true);
                PEData chunkedData = PELoader.loadPE(file);
                List<String> chunkedSnapshot = clrTableSnapshot(chunkedData);

                Mapping$.MODULE$.useChunks_$eq(false);
                PEData unchunkedData = PELoader.loadPE(file);
                List<String> unchunkedSnapshot = clrTableSnapshot(unchunkedData);

                assertEquals(chunkedSnapshot, unchunkedSnapshot, fixture);
            }
        } finally {
            Mapping$.MODULE$.useChunks_$eq(originalUseChunks);
        }
    }

    @Test
    public void metadataHeapsAndOptimizedTablesExposeConsistentRows() throws IOException {
        PEData data = PELoader.loadPE(fixtureFile("HelloWorld.exe"));
        CLRSection clr = new SectionLoader(data).loadCLRSection();
        MetadataRoot root = clr.metadataRoot();
        OptimizedStream stream = root.maybeGetOptimizedStream().get();
        StringsHeap strings = root.maybeGetStringsHeap().get();
        GuidHeap guids = root.maybeGetGuidHeap().get();
        BlobHeap blobs = root.maybeGetBlobHeap().get();

        assertTrue(root.getStreamHeaders().size() >= 4);
        assertTrue(strings.getSizeInBytes() > 1);
        assertTrue(strings.getArray().length > 0);
        assertNotNull(strings.get(1));
        assertEquals(stream.getStringHeapSize(), strings.getIndexSize());
        assertEquals(stream.getGUIDHeapSize(), guids.getIndexSize());
        assertEquals(stream.getBlobHeapSize(), blobs.getIndexSize());

        assertTrue(stream.getTableIndices().nonEmpty());
        assertTrue(stream.getTableNames().contains("Module"));
        assertTrue(stream.getCLRTable(CLRTableType.MODULE).isDefined());
        CLRTable moduleTable = stream.getCLRTable(CLRTableType.MODULE).get();
        assertEquals(moduleTable.getTableName(), "Module");
        assertTrue(moduleTable.getEntryByRow(1).isDefined());

        CLRTableEntry module = moduleTable.getEntryByRow(1).get();
        CLRField name = module.get(CLRTableKey.MODULE_NAME).get();
        assertTrue(name instanceof CLRStringField);
        assertTrue(((CLRStringField) name).getString().length() > 0);
        assertTrue(module.getCLRFieldsAsStandardFields().size() > 0);
    }

    @Test
    public void everyImplementedClrTableHasMetadataAndAReadableSpecification() {
        scala.collection.Iterator<?> indices = CLRTable.getImplementedCLRIndices().iterator();
        assertTrue(CLRTable.getImplementedCLRIndices().size() > 0);
        while (indices.hasNext()) {
            Integer index = (Integer) indices.next();
            CLRTableMeta metadata = CLRTable.getTableMetaForIndex(index);
            assertEquals(metadata.index(), index.intValue());
            assertNotNull(metadata.name());
            assertNotNull(metadata.specName());
            assertTrue(CLRTable.readSpecificationFromFile(index).nonEmpty(), metadata.name());
        }
    }

    @Test
    public void codedTagMappingsCoverValidNullAndOutOfRangeTags() {
        for (TagType tagType : TagType.values()) {
            CLRTableType[] tables = tagType.getAllTables();
            for (int tag = 0; tag < tables.length; tag++) {
                Optional<CLRTableType> actual = tagType.getTableForTag(tag);
                if (tables[tag] == null) {
                    assertFalse(actual.isPresent(), tagType + " tag " + tag);
                } else {
                    assertEquals(actual.get(), tables[tag], tagType + " tag " + tag);
                }
            }
            assertFalse(tagType.getTableForTag(tables.length).isPresent());
        }

        assertEquals(TagType.getTagTypeForCLRTableKey(CLRTableKey.TYPEDEF_EXTENDS).get(),
                TagType.TYPEDEF_OR_REF);
        assertFalse(TagType.getTagTypeForCLRTableKey(CLRTableKey.MODULE_NAME).isPresent());
        assertEquals(Arrays.stream(CLRTableType.values()).map(CLRTableType::getIndex).distinct().count(),
            (long) CLRTableType.values().length);
    }

    @Test
    public void clrFlagDescriptionsAndCliHeaderFieldsAreCovered() throws IOException {
        assertEquals(CLRTable.getDescriptionForTableFlag(0, CLRTableKey.ASSEMBLY_HASHALGID).get(), "None");
        assertEquals(CLRTable.getDescriptionForTableFlag(0x8004, CLRTableKey.ASSEMBLY_HASHALGID).get(), "SHA1");
        assertEquals(CLRTable.getDescriptionForTableFlag(7, CLRTableKey.ASSEMBLY_HASHALGID).get(), "unknown HashId");
        assertEquals(CLRTable.getDescriptionForTableFlag(1, CLRTableKey.ASSEMBLY_FLAGS).get(), "PublicKey");
        assertEquals(CLRTable.getDescriptionForTableFlag(0x20, CLRTableKey.ASSEMBLY_FLAGS).get(), "unknown flag");
        assertEquals(CLRTable.getDescriptionForTableFlag(2, CLRTableKey.MANIFESTRESOURCE_FLAGS).get(), "Private");
        assertFalse(CLRTable.getDescriptionForTableFlag(1, CLRTableKey.MODULE_NAME).isDefined());

        List<ComImageFlag> setFlags = ComImageFlag.getAllFor(0x00000003L);
        assertTrue(setFlags.contains(ComImageFlag.COMIMAGE_FLAGS_ILONLY));
        assertTrue(setFlags.contains(ComImageFlag.COMIMAGE_FLAGS_32BITREQUIRED));
        assertEquals(setFlags.size(), 2);
        assertTrue(ComImageFlag.getAllFor(0x80000000L).isEmpty());
        for (ComImageFlag flag : ComImageFlag.values()) {
            assertNotNull(flag.getDescription());
            assertTrue(flag.getValue() != 0);
            assertFalse(flag.isReserved());
            assertFalse(flag.isDeprecated());
        }

        CLRSection clr = new SectionLoader(PELoader.loadPE(fixtureFile("HelloWorld.exe"))).loadCLRSection();
        assertEquals(clr.getCliHeaderEntries().size(), CLIHeaderKey.values().length);
        assertTrue(clr.getCliHeaderEntries().containsKey(CLIHeaderKey.META_DATA_RVA));
        assertTrue(clr.getPhysicalLocations().size() >= 2);
        assertTrue(clr.getInfo().contains("Flags:"));
    }

    @Test
    public void clrFieldVariantsAndHeapIndexBoundsAreConsistent() throws IOException {
        PEData data = PELoader.loadPE(fixtureFile("HelloWorld.exe"));
        CLRSection clr = new SectionLoader(data).loadCLRSection();
        MetadataRoot root = clr.metadataRoot();
        StringsHeap strings = root.maybeGetStringsHeap().get();
        GuidHeap guids = root.maybeGetGuidHeap().get();
        BlobHeap blobs = root.maybeGetBlobHeap().get();
        OptimizedStream stream = root.maybeGetOptimizedStream().get();

        boolean sawString = false;
        boolean sawGuid = false;
        boolean sawBlob = false;
        boolean sawCodedIndex = false;
        boolean sawFlag = false;
        boolean sawLong = false;
        for (CLRTable table : stream.getCLRTables()) {
            for (CLRTableEntry row : table.getEntries()) {
                assertNotNull(row.getShortDescription());
                assertNotNull(row.toString());
                for (CLRField field : row.getCLRFields().values()) {
                    assertNotNull(field.toStandardField());
                    if (field instanceof CLRStringField) {
                        sawString = true;
                        CLRStringField stringField = (CLRStringField) field;
                        int index = stringField.getNIndex().getIndex();
                        if (index > 0) assertNotNull(stringField.getString());
                        else assertEquals(stringField.getDescription(), "0x0");
                    } else if (field instanceof CLRGuidField) {
                        sawGuid = true;
                        CLRGuidField guidField = (CLRGuidField) field;
                        if (guidField.getNIndex() instanceof GuidIndex &&
                                ((GuidIndex) guidField.getNIndex()).isValid()) {
                            assertNotNull(guidField.getGuid());
                        }
                    } else if (field instanceof CLRBlobField) {
                        sawBlob = true;
                        CLRBlobField blobField = (CLRBlobField) field;
                        assertNotNull(blobField.getNIndex());
                        if (blobField.getNIndex() instanceof BlobIndex &&
                                ((BlobIndex) blobField.getNIndex()).isValid()) {
                            assertNotNull(blobField.getNIndex());
                        }
                    } else if (field instanceof CLRCodedIndexField) {
                        sawCodedIndex = true;
                        CLRCodedIndexField coded = (CLRCodedIndexField) field;
                        assertEquals(coded.getValue(), ((CodedTokenIndex) coded.getNIndex()).getCodedToken());
                        assertEquals(coded.getReferencedRow(), coded.getNIndex().getIndex());
                        assertNotNull(coded.getValueAsObject());
                    } else if (field instanceof CLRFlagField) {
                        sawFlag = true;
                        assertNotNull(field.getValueAsObject());
                    } else if (field instanceof CLRLongField) {
                        sawLong = true;
                    }
                }
            }
        }

        assertTrue(sawString);
        assertTrue(sawGuid);
        assertTrue(sawBlob);
        assertTrue(sawCodedIndex);
        assertTrue(sawFlag);
        assertTrue(sawLong);
        assertFalse(new GuidIndex(0, some(guids)).isValid());
        assertFalse(new GuidIndex(guids.getNumberOfGuids() + 1, some(guids)).isValid());
        assertTrue(new GuidIndex(1, some(guids)).isValid());
        assertFalse(new GuidIndex(1, none()).isValid());
        assertFalse(new StringIndex((int) strings.getSizeInBytes(), some(strings)).isValid());
        assertTrue(new StringIndex(1, some(strings)).isValid());
        assertTrue(new BlobIndex(0, some(blobs)).isValid());
        assertEquals(new BlobIndex(0, some(blobs)).getValue().get().length, 0);
        assertFalse(new BlobIndex((int) blobs.getSizeInBytes(), some(blobs)).isValid());
        assertFalse(new BlobIndex(1, none()).isValid());
    }

    @Test
    public void clrTableRowLookupReturnsRowsAtTheirOneBasedPositions() throws IOException {
        PEData data = PELoader.loadPE(fixtureFile("HelloWorld.exe"));
        for (CLRTable table : data.getCLRTables()) {
            List<CLRTableEntry> entries = table.getEntries();
            for (CLRTableEntry entry : entries) {
                assertEquals(table.getEntryByRow(entry.row()).get(), entry);
            }
            assertFalse(table.getEntryByRow(entries.size() + 1).isDefined());
        }
    }

    @Test
    public void chunkReadsMatchFileBytesAcrossBoundariesAndPartialTail() throws IOException {
        boolean originalUseChunks = Mapping$.MODULE$.useChunks();
        int originalChunkSize = Mapping$.MODULE$.defaultChunkSize();
        try {
            File file = fixtureFile("HelloWorld.exe");
            byte[] fileBytes = Files.readAllBytes(file.toPath());
            PEData data = PELoader.loadPE(file);
            Mapping$.MODULE$.useChunks_$eq(true);
            Mapping$.MODULE$.defaultChunkSize_$eq(31);
            Mapping mapping = new Mapping(new VirtRange(0, fileBytes.length),
                    new PhysRange(0, fileBytes.length), data);

            assertSliceEquals(fileBytes, mapping, 28, 79);
            assertSliceEquals(fileBytes, mapping, fileBytes.length - 71, 71);
        } finally {
            Mapping$.MODULE$.defaultChunkSize_$eq(originalChunkSize);
            Mapping$.MODULE$.useChunks_$eq(originalUseChunks);
        }
    }

    @Test
    public void clrFieldIterationFollowsSpecificationAndPedataColumnsStayAligned() throws IOException {
        PEData data = PELoader.loadPE(fixtureFile("HelloWorld.exe"));
        Map<String, List<String>> headersByTable = data.loadCLRTableHeaders();
        Map<String, List<List<Object>>> rowsByTable = data.loadCLRTables();

        for (CLRTable table : data.getCLRTables()) {
            List<CLRTableEntry> entries = table.getEntries();
            if (entries.isEmpty()) continue;

            CLRTableEntry firstEntry = entries.get(0);
            List<CLRTableKey> expectedKeys = new ArrayList<>();
            scala.collection.Iterator<?> specRows = CLRTable.readSpecificationFromFile(table.getIndex()).iterator();
            while (specRows.hasNext()) {
                String[] specRow = (String[]) specRows.next();
                CLRTableKey key = CLRTableKey.valueOf(specRow[0]);
                if (firstEntry.getCLRFields().containsKey(key)) expectedKeys.add(key);
            }
            assertEquals(new ArrayList<>(firstEntry.getCLRFields().keySet()), expectedKeys,
                    table.getTableName() + " field order");

            String tableLabel = String.format("%0#4x %s", table.getIndex(), table.getTableName());
            List<String> expectedHeaders = new ArrayList<>();
            expectedHeaders.add("Row");
            for (CLRField field : firstEntry.getCLRFields().values()) expectedHeaders.add(field.getName());
            expectedHeaders.add("File offset");
            assertEquals(headersByTable.get(tableLabel), expectedHeaders, tableLabel + " headers");

            List<List<Object>> tableRows = rowsByTable.get(tableLabel);
            assertEquals(tableRows.size(), entries.size(), tableLabel + " row count");
            for (int rowIndex = 0; rowIndex < entries.size(); rowIndex++) {
                CLRTableEntry entry = entries.get(rowIndex);
                List<Object> expectedValues = new ArrayList<>();
                expectedValues.add(entry.row());
                for (CLRField field : entry.getCLRFields().values()) expectedValues.add(field.getValueAsObject());
                expectedValues.add(entry.rawOffset());
                assertEquals(tableRows.get(rowIndex), expectedValues, tableLabel + " row " + entry.row());
            }
        }
    }

    private static File fixtureFile(String name) {
        return Paths.get(TestreportsReader.RESOURCE_DIR, "testfiles", name).toFile();
    }

            private static <T> scala.Option<T> some(T value) {
            return scala.Option$.MODULE$.apply(value);
            }

            private static <T> scala.Option<T> none() {
            return scala.Option$.MODULE$.empty();
            }

    private static List<String> clrTableSnapshot(PEData data) {
        List<CLRTable> tables = new ArrayList<>(data.getCLRTables());
        tables.sort(Comparator.comparingInt(CLRTable::getIndex));
        List<String> snapshot = new ArrayList<>();
        for (CLRTable table : tables) {
            snapshot.add("table:" + table.getIndex() + ":" + table.getTableName());
            for (CLRTableEntry row : table.getEntries()) {
                snapshot.add("row:" + row.row() + ":" + row.rawOffset());
                List<CLRTableKey> keys = new ArrayList<>(row.getCLRFields().keySet());
                keys.sort(Comparator.comparing(Enum::name));
                for (CLRTableKey key : keys) {
                    CLRField field = row.getCLRFields().get(key);
                    snapshot.add(key.name() + ":" + field.getClass().getName() + ":" +
                            field.getValue() + ":" + field.getDescription());
                }
            }
        }
        return snapshot;
    }

    private static void assertSliceEquals(byte[] expected, Mapping mapping, int offset, int length) {
        assertEquals(mapping.apply(offset, length), Arrays.copyOfRange(expected, offset, offset + length));
    }
}