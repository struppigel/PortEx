package io.github.struppigel.tools.anomalies;

import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoaderTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import static io.github.struppigel.tools.anomalies.AnomalyType.NON_DEFAULT;
import static io.github.struppigel.tools.anomalies.PEAnomalyScannerTest.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class OverlayScanningTest {
    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }
    @Test
    public void checkPyInstaller(){
        PEData pyinstaller = pedata.get("pyinstaller");
        assertHasAnomalySubTypeWithDescription(pyinstaller, AnomalySubType.RE_HINT, "PyInstaller");
        assertHasAnomalyType(pyinstaller, NON_DEFAULT);
    }
}
