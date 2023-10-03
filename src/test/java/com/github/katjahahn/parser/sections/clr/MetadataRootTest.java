package com.github.katjahahn.parser.sections.clr;

import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoaderTest;
import com.github.katjahahn.parser.sections.SectionLoader;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.Map;
import static org.testng.Assert.*;

public class MetadataRootTest{

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
            assertEquals(root.getBSJBOffset(),612);
            assertEquals(root.getStreamHeaders().size(), 5);
            assertTrue(root.maybeGetBlobHeap().isPresent());
            assertTrue(root.maybeGetGuidHeap().isPresent());
            assertTrue(root.maybeGetStringsHeap().isPresent());
            assertTrue(root.maybeGetOptimizedStream().isPresent());

            datum = pedata.get("HelloWorld.TablesStream.ExtraData.exe");
            clr = new SectionLoader(datum).loadCLRSection();
            root = clr.metadataRoot();
            assertEquals(root.getBSJBOffset(),612);
            assertEquals(root.getStreamHeaders().size(), 5);
            assertTrue(root.maybeGetBlobHeap().isPresent());
            assertTrue(root.maybeGetGuidHeap().isPresent());
            assertTrue(root.maybeGetStringsHeap().isPresent());
            assertTrue(root.maybeGetOptimizedStream().isPresent());

        }

}
