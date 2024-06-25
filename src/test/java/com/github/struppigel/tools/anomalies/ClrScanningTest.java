package com.github.struppigel.tools.anomalies;

import com.github.struppigel.parser.PEData;
import com.github.struppigel.parser.PELoaderTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import static com.github.struppigel.tools.anomalies.AnomalySubType.*;
import static com.github.struppigel.tools.anomalies.PEAnomalyScannerTest.assertHasAnomalyOfType;
import static com.github.struppigel.tools.anomalies.PEAnomalyScannerTest.assertHasNotAnomalyOfType;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ClrScanningTest {

    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void nonZeroTerminatedStreamHeaderNameAnomaly() throws IOException {
        PEData pe = pedata.get("NetCoreConsole_BrokenStreamName.dll");
        assertHasAnomalyOfType(pe, NON_ZERO_TERMINATED_STREAM_NAME);
        PEData peNormal = pedata.get("HelloWorld.exe");
        assertHasNotAnomalyOfType(peNormal, NON_ZERO_TERMINATED_STREAM_NAME);
    }

    @Test
    public void versionStringMetaDataRootNotReadable() {
        PEData pe = pedata.get("HelloWorld_BrokenMetaRootVersionString.exe");
        assertHasAnomalyOfType(pe, METADATA_ROOT_VERSION_STRING_BROKEN);
        PEData peNormal = pedata.get("HelloWorld.exe");
        assertHasNotAnomalyOfType(peNormal, METADATA_ROOT_VERSION_STRING_BROKEN);
    }
}
