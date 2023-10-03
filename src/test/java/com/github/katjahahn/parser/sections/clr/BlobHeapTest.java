package com.github.katjahahn.parser.sections.clr;

import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoaderTest;
import com.github.katjahahn.parser.sections.SectionLoader;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class BlobHeapTest {
    private Map<String, PEData> pedata;

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void basicWorkingTest() throws IOException {
        PEData datum = pedata.get("HelloWorld.exe");
        CLRSection clr = new SectionLoader(datum).loadCLRSection();
        MetadataRoot root = clr.metadataRoot();
        BlobHeap blob = root.maybeGetBlobHeap().get();
        assertEquals(blob.getIndexSize(), 2);
        assertEquals(blob.getSizeInBytes(), 216);
        assertEquals(blob.get(0).length, 0);
        assertEquals(blob.get(2).length, 32);

        datum = pedata.get("HelloWorld.TablesStream.ExtraData.exe");
        clr = new SectionLoader(datum).loadCLRSection();
        root = clr.metadataRoot();
        blob = root.maybeGetBlobHeap().get();
        assertEquals(blob.getIndexSize(), 2);
        assertEquals(blob.getSizeInBytes(), 216);
        assertEquals(blob.get(0).length, 0);
        assertEquals(blob.get(2).length, 14202);
    }
}
