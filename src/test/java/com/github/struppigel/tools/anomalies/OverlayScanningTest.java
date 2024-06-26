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

public class OverlayScanningTest {
    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void checkPyInstaller(){
        PEData pyinstaller = pedata.get("pyinstaller");
        assertHasAnomalySubTypeWithDescription(pyinstaller, PYINSTALLER_RE_HINT, "PyInstaller");
        assertHasAnomalyType(pyinstaller, RE_HINT);
    }
}
