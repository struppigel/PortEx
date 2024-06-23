package com.github.struppigel.tools.anomalies;

import com.github.struppigel.parser.PEData;
import com.github.struppigel.parser.PELoaderTest;
import com.github.struppigel.parser.sections.SectionLoader;
import com.github.struppigel.parser.sections.clr.CLRSection;
import com.github.struppigel.tools.ReportCreator;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import static com.github.struppigel.tools.anomalies.AnomalySubType.*;
import static org.testng.Assert.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ClrScanningTest {

    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }

    private void assertHasAnomalyOfType(PEData pe, AnomalySubType atype) {
        PEAnomalyScanner scanner = PEAnomalyScanner.newInstance(pe.getFile());
        List<Anomaly> anomalies = scanner.getAnomalies();
        List<Anomaly> found = anomalies.stream()
                .filter(a -> a.subtype() == atype)
                .collect(Collectors.toList());
        assertTrue(found.size() > 0);
    }

    private void assertHasNotAnomalyOfType(PEData pe, AnomalySubType atype) {
        PEAnomalyScanner scanner = PEAnomalyScanner.newInstance(pe.getFile());
        List<Anomaly> anomalies = scanner.getAnomalies();
        List<Anomaly> found = anomalies.stream()
                .filter(a -> a.subtype() == atype)
                .collect(Collectors.toList());
        assertTrue(found.isEmpty());
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
