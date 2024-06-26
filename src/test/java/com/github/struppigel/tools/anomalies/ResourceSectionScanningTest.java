package com.github.struppigel.tools.anomalies;

import com.github.struppigel.parser.PEData;
import com.github.struppigel.parser.PELoaderTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import static com.github.struppigel.tools.anomalies.AnomalySubType.*;
import static com.github.struppigel.tools.anomalies.AnomalyType.RE_HINT;
import static com.github.struppigel.tools.anomalies.PEAnomalyScannerTest.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ResourceSectionScanningTest {
    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void ahkTest() {
        PEData pe = pedata.get("ahk");
        assertHasAnomalySubType(pe, AHK_RE_HINT);
        assertHasAnomalyType(pe, RE_HINT);
    }

    @Test
    public void autoitTest() {
        PEData pe = pedata.get("autoit");
        assertHasAnomalySubType(pe, AUTOIT_RE_HINT);
        assertHasAnomalyType(pe, RE_HINT);
    }
}
