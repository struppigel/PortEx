package com.github.struppigel.parser.sections.clr;

import com.github.struppigel.parser.PEData;
import com.github.struppigel.parser.PELoaderTest;
import com.github.struppigel.parser.sections.SectionLoader;
import com.github.struppigel.tools.ReportCreator;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.Map;

import static org.testng.Assert.*;

public class CLRSectionTest {
    private Map<String, PEData> pedata;

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void basicWorkingTest() throws IOException {
        PEData datum = pedata.get("HelloWorld.exe");
        CLRSection clr = new SectionLoader(datum).loadCLRSection();
        assertEquals(clr.getOffset(), 520);
        assertEquals(clr.cliHeader().size(), 14 );
        assertEquals( clr.metadataRoot().offset(), 612);
        assertTrue( clr.getInfo().length() > 0);
        assertTrue(clr.getPhysicalLocations().size() > 0);
        assertFalse(clr.isEmpty());

        // just making sure it does not crash or hang
        ReportCreator reportCreator = new ReportCreator(datum);
        reportCreator.clrReport();

        datum = pedata.get("HelloWorld.TablesStream.ExtraData.exe");
        clr = new SectionLoader(datum).loadCLRSection();
        assertEquals(clr.getOffset(), 520);
        assertEquals(clr.cliHeader().size(), 14 );
        assertEquals(clr.metadataRoot().offset(), 612);
        assertTrue( clr.getInfo().length() > 0);
        assertTrue(clr.getPhysicalLocations().size() > 0);
        assertFalse(clr.isEmpty());

        // just making sure it does not crash or hang
        reportCreator = new ReportCreator(datum);
        reportCreator.clrReport();
    }

}
