package com.github.katjahahn.parser.sections.debug;
import static com.github.katjahahn.parser.sections.debug.DebugDirectoryKey.*;
import static org.testng.Assert.*;

import java.io.IOException;
import java.util.Map;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoaderTest;
import com.github.katjahahn.parser.sections.SectionLoader;

public class DebugSectionTest {

    private Map<String, PEData> pedata;

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void basicWorkingTest() throws IOException {
        PEData datum = pedata.get("strings.exe");
        DebugSection debug = new SectionLoader(datum).loadDebugSection();
        assertEquals((long) debug.get(MAJOR_VERSION), 0L);
        assertEquals((long) debug.get(MINOR_VERSION), 0L);
        assertEquals((long) debug.get(ADDR_OF_RAW_DATA), 323836L);
        assertEquals((long) debug.get(SIZE_OF_DATA), 71L);
        assertEquals((long) debug.get(POINTER_TO_RAW_DATA), 317180L);
        assertEquals((long) debug.get(CHARACTERISTICS), 0L);
        assertEquals(debug.getTypeDescription(), "Visual C++ debug information");
        assertEquals(debug.getDebugType(), DebugType.CODEVIEW);
    }
}
