package com.github.katjahahn.parser;

import com.github.katjahahn.TestreportsReader;
import com.github.katjahahn.parser.sections.debug.CodeviewInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.*;

import static org.testng.Assert.*;

public class PEDataTest {

    private static final Logger logger = LogManager.getLogger(PEDataTest.class
            .getName());

    private List<TestreportsReader.TestData> testdata;
    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        testdata = PELoaderTest.getTestData();
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void loadPDBPath() {
        PEData data = pedata.get("WMIX.exe");
        String pdb = data.loadPDBPath();
        assertEquals(pdb, "C:\\CodeBases\\isdev\\redist\\Language Independent\\i386\\setupPreReq.pdb");
        assertEquals(pdb, data.loadCodeViewInfo().get().filePath());
    }

    @Test
    public void loadCodeview() {
        Optional<CodeviewInfo> codeView = pedata.get("WMIX.exe").loadCodeViewInfo();
        byte[] guid = {36, 88, 100, -120, 25, 75, 48, 66, -106, -88, -40, 71, 118, -90, -83, 110};
        assertTrue(codeView.isPresent());
        assertEquals(codeView.get().filePath(), "C:\\CodeBases\\isdev\\redist\\Language Independent\\i386\\setupPreReq.pdb");
        assertEquals(codeView.get().age(), 1L);
        assertEquals(codeView.get().guid(), guid);
    }

    @Test
    public void loadImports(){
        // some imports
        assertEquals(pedata.get("WMIX.exe").loadImports().size(), 11);
        assertTrue(pedata.get("WMIX.exe").hasImports());
        // no imports
        assertEquals(pedata.get("smallest-pe.exe").loadImports().size(), 0);
        assertFalse(pedata.get("smallest-pe.exe").hasImports());
    }

    @Test
    public void loadExports(){
        // some exports
        assertEquals(pedata.get("Lab17-02dll").loadExports().size(), 9);
        assertTrue(pedata.get("Lab17-02dll").hasExports());
        // no exports
        assertEquals(pedata.get("smallest-pe.exe").loadExports().size(), 0);
        assertFalse(pedata.get("smallest-pe.exe").hasExports());
    }

    @Test
    public void loadResources(){
        assertEquals(pedata.get("WMIX.exe").loadResources().size(), 69);
        assertEquals(pedata.get("smallest-pe.exe").loadResources().size(), 0);
    }

    @Test
    public void loadManifest(){
        PEData wmic = pedata.get("WMIX.exe");

        assertEquals(wmic.loadManifests().size(), 2);
        assertEquals(wmic.loadManifests(1333).size(), 2);
        assertEquals(wmic.loadManifests(1332).size(), 1);
        assertEquals(wmic.loadManifests().size(), 1); // still same size
        assertEquals(wmic.loadManifests(0).size(), 0);
        assertEquals(wmic.loadManifests().size(), 0); // still same size
        assertEquals(pedata.get("smallest-pe.exe").loadManifests().size(), 0);

        assertEquals(wmic.loadManifests(1333).get(0).length(), 1333);
        assertEquals(wmic.loadManifests(1333).get(1).length(), 638);
        assertEquals(wmic.loadManifests(1332).get(0).length(), 638);
        assertEquals(wmic.loadManifests().get(0).length(), 638); // still same size

        wmic.setMaxManifestSize(1333);
        assertEquals(wmic.loadManifests().size(), 2);
        wmic.setMaxManifestSize(1332);
        assertEquals(wmic.loadManifests().size(), 1);
        wmic.setMaxManifestSize(0);
        assertEquals(wmic.loadManifests().size(), 0);
    }

    @Test
    public void loadVersionInfo(){
        assertTrue(pedata.get("WMIX.exe").loadVersionInfo().isPresent());
        assertTrue(pedata.get("WMIX.exe").hasVersionInfo());
        assertFalse(pedata.get("smallest-pe.exe").loadVersionInfo().isPresent());
        assertFalse(pedata.get("smallest-pe.exe").hasVersionInfo());
    }

    @Test
    public void hasGroupIcon(){
        assertTrue(pedata.get("WMIX.exe").hasGroupIcon());
        assertFalse(pedata.get("smallest-pe.exe").hasGroupIcon());
    }

    @Test
    public void loadIcons(){
        assertEquals(pedata.get("WMIX.exe").loadIcons().size(),3);
        assertEquals(pedata.get("smallest-pe.exe").loadIcons().size(), 0);
    }
}
