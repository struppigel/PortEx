package io.github.struppigel.parser.sections.clr;

import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoaderTest;
import io.github.struppigel.parser.ScalaIOUtil;
import io.github.struppigel.parser.sections.SectionLoader;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.Map;

import static org.testng.Assert.assertEquals;

public class GuidHeapTest {
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
        GuidHeap guid = root.maybeGetGuidHeap().get();
        assertEquals(guid.getIndexSize(), 2);
        assertEquals(guid.getSizeInBytes(), 16);
        byte[] heapDump = guid.getHeapDump();
        assertEquals(guid.getHeapDump().length, (int) guid.getSizeInBytes());
        assertEquals(ScalaIOUtil.convertBytesToUUID(heapDump), guid.get(1));
        assertEquals(guid.getOffset(), 9308);
        assertEquals(guid.get(1).toString().toUpperCase(), "22BD2433-09CA-4F27-B62A-BE3CB68DE75E");

        datum = pedata.get("HelloWorld.TablesStream.ExtraData.exe");
        clr = new SectionLoader(datum).loadCLRSection();
        root = clr.metadataRoot();
        guid = root.maybeGetGuidHeap().get();
        assertEquals(guid.getIndexSize(), 2);
        assertEquals(guid.getSizeInBytes(), 16);
        heapDump = guid.getHeapDump();
        assertEquals(guid.getHeapDump().length, (int) guid.getSizeInBytes());
        assertEquals(ScalaIOUtil.convertBytesToUUID(heapDump), guid.get(1));
        assertEquals(guid.getOffset(), 9308);
        assertEquals(guid.get(1).toString().toUpperCase(), "22BD2433-09CA-4F27-B62A-BE3CB68DE75E");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void guidIndexTooHigh() throws IOException {
        PEData datum = pedata.get("HelloWorld.exe");
        CLRSection clr = new SectionLoader(datum).loadCLRSection();
        MetadataRoot root = clr.metadataRoot();
        GuidHeap guid = root.maybeGetGuidHeap().get();
        guid.get(2); // must fail
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void guidIndexTooLow() throws IOException {
        PEData datum = pedata.get("HelloWorld.exe");
        CLRSection clr = new SectionLoader(datum).loadCLRSection();
        MetadataRoot root = clr.metadataRoot();
        GuidHeap guid = root.maybeGetGuidHeap().get();
        guid.get(0); // must fail
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void guidOffsetTooLow() throws IOException {
        PEData datum = pedata.get("HelloWorld.exe");
        CLRSection clr = new SectionLoader(datum).loadCLRSection();
        MetadataRoot root = clr.metadataRoot();
        GuidHeap guid = root.maybeGetGuidHeap().get();
        guid.getGUIDAtHeapOffset(-1); // must fail
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void guidOffsetTooHigh() throws IOException {
        PEData datum = pedata.get("HelloWorld.exe");
        CLRSection clr = new SectionLoader(datum).loadCLRSection();
        MetadataRoot root = clr.metadataRoot();
        GuidHeap guid = root.maybeGetGuidHeap().get();
        guid.getGUIDAtHeapOffset(1); // must fail
    }
}
