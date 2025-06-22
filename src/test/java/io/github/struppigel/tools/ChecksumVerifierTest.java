package io.github.struppigel.tools;

import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoaderTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import static org.testng.Assert.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ChecksumVerifierTest {
    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void hasValidChecksum(){
        assertFalse(ChecksumVerifier.hasValidChecksum(pedata.get("Lab05-01")));
        assertTrue(ChecksumVerifier.hasValidChecksum(pedata.get("strings.exe")));
    }

    @Test
    public void calcChecksum(){
        PEData pe = pedata.get("Lab05-01");
        long checksum = ChecksumVerifier.computeChecksum(pe);
        PEData pe2 = pedata.get("WMIX.exe");
        long checksum2 = ChecksumVerifier.computeChecksum(pe2);

        assertEquals(checksum, 0x25e02);
        assertEquals(checksum2, 0x30A54B1);
    }


}
