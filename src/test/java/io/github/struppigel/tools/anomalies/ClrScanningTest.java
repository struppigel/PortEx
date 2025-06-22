package io.github.struppigel.tools.anomalies;

import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoaderTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import static io.github.struppigel.tools.anomalies.AnomalySubType.*;
import static io.github.struppigel.tools.anomalies.PEAnomalyScannerTest.assertHasAnomalySubType;
import static io.github.struppigel.tools.anomalies.PEAnomalyScannerTest.assertHasNotAnomalySubType;

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
    public void nonZeroTerminatedStreamHeaderNameAnomaly() {
        PEData pe = pedata.get("NetCoreConsole_BrokenStreamName.dll");
        assertHasAnomalySubType(pe, NON_ZERO_TERMINATED_STREAM_NAME);
        PEData peNormal = pedata.get("HelloWorld.exe");
        assertHasNotAnomalySubType(peNormal, NON_ZERO_TERMINATED_STREAM_NAME);
    }

    @Test
    public void versionStringMetaDataRootNotReadable() {
        PEData pe = pedata.get("HelloWorld_BrokenMetaRootVersionString.exe");
        assertHasAnomalySubType(pe, METADATA_ROOT_VERSION_STRING_BROKEN);
        PEData peNormal = pedata.get("HelloWorld.exe");
        assertHasNotAnomalySubType(peNormal, METADATA_ROOT_VERSION_STRING_BROKEN);
    }
}
