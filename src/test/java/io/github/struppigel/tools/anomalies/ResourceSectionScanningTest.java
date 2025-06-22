package io.github.struppigel.tools.anomalies;

import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoaderTest;
import org.testng.annotations.BeforeClass;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ResourceSectionScanningTest {
    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }

}
