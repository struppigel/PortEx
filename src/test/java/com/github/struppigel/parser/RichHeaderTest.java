package com.github.struppigel.parser;

import com.github.struppigel.TestreportsReader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RichHeaderTest {
    private static final Logger logger = LogManager.getLogger(PEDataTest.class
            .getName());

    private List<TestreportsReader.TestData> testdata;
    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        testdata = PELoaderTest.getTestData();
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void richHeader(){
        PEData data = pedata.get("nothing.exe"); // this one caused problems
        data.maybeGetRichHeader();
    }
}
