package com.github.struppigel.tools.anomalies;

import com.github.struppigel.parser.PEData;
import com.github.struppigel.parser.PELoaderTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import static com.github.struppigel.tools.anomalies.PEAnomalyScannerTest.assertHasAnomalyOfType;
import static com.github.struppigel.tools.anomalies.PEAnomalyScannerTest.assertHasNotAnomalyOfType;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ComplexReHintScanningTest {

    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void checkElectronPackageTest() {
        PEData pe = pedata.get("electron.exe"); // this file is a fake electron package just so we detect the anomaly
        assertHasAnomalyOfType(pe, AnomalySubType.ELECTRON_PACKAGE_RE_HINT);
        PEData penormal = pedata.get("Hello.exe");
        assertHasNotAnomalyOfType(penormal, AnomalySubType.ELECTRON_PACKAGE_RE_HINT);
    }
}
