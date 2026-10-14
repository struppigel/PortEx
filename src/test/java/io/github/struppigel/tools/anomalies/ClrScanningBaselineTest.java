package io.github.struppigel.tools.anomalies;

import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoaderTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import static org.testng.Assert.assertEquals;

/**
 * The anomaly subtypes reported for unmodified .NET files are pinned. A new CLR subtype that fires on one of
 * these files is either a false positive or a property of the file that must be understood and documented here.
 */
public class ClrScanningBaselineTest {

    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }

    private Set<String> subtypes(String file) {
        return PEAnomalyScanner.newInstance(pedata.get(file)).getAnomalies().stream()
                .map(a -> a.subtype().name())
                .collect(Collectors.toCollection(TreeSet::new));
    }

    private static Set<String> set(String... names) {
        return new TreeSet<>(Arrays.asList(names));
    }

    @Test
    public void helloWorldHasOnlyTheTimeStampAnomaly() {
        assertEquals(subtypes("HelloWorld.exe"), set("TIME_DATE_IN_FUTURE"));
    }

    @Test
    public void netCoreConsoleHasOnlyTheTimeStampAnomaly() {
        assertEquals(subtypes("NetCoreConsole.dll"), set("TIME_DATE_IN_FUTURE"));
    }

    @Test
    public void dotNetBundleHasOnlyNativeAnomalies() {
        assertEquals(subtypes("DotNetBundle.exe"), set("NON_DEFAULT_IMAGE_BASE", "OVERLAY_HAS_SIGNATURE",
                "PROCESS_INJECTION_OR_UNPACKING_IMPORT", "TOO_LARGE_IMAGE_BASE", "UNUSUAL_SEC_NAME"));
    }
}
