package com.github.katjahahn.parser.sections.rdata;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.TestreportsReader;
import com.github.katjahahn.TestreportsReader.TestData;
import com.github.katjahahn.parser.FileFormatException;
import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoader;
import com.github.katjahahn.parser.PELoaderTest;
import com.github.katjahahn.parser.sections.SectionLoader;
import com.github.katjahahn.parser.sections.rsrc.IDOrName;
import com.github.katjahahn.parser.sections.rsrc.Level;
import com.github.katjahahn.parser.sections.rsrc.Name;
import com.github.katjahahn.parser.sections.rsrc.Resource;
import com.github.katjahahn.parser.sections.rsrc.ResourceSection;
import com.google.common.base.Optional;

public class ResourceSectionTest {

    private List<TestData> testdata;
    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        testdata = PELoaderTest.getTestData();
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void resourceLoopRobustness() throws IOException {
        String[] actResources = { "offset: 0x1370, size: 0x229, language -> ID: 0, name -> ID: 101, type -> ID: RT_RCDATA" };
        PEData data = PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR
                + "/unusualfiles/corkami/resource_loop.exe"));
        List<Resource> resources = new SectionLoader(data)
                .loadResourceSection().getResources();
        assertEquals(actResources.length, resources.size());
        for (int i = 0; i < actResources.length; i++) {
            assertEquals(actResources[i], resources.get(i).toString());
        }
    }
    
    @Test
    public void shuffledResourcesRobustness() throws IOException {
        String[] actResources = { "offset: 0x12f0, size: 0x229, language -> ID: 0, name -> ID: 101, type -> ID: RT_RCDATA" };
        PEData data = PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR
                + "/unusualfiles/corkami/resource_shuffled.exe"));
        List<Resource> resources = new SectionLoader(data)
                .loadResourceSection().getResources();
        assertEquals(actResources.length, resources.size());
        for (int i = 0; i < actResources.length; i++) {
            assertEquals(actResources[i], resources.get(i).toString());
        }
    }

    @Test
    public void readWinRarResources() throws IOException {
        String[] actResources = {
                "offset: 0x12a04, size: 0x36b0, language -> ID: 1049, name -> TITLE_BMP, type -> ID: RT_BITMAP",
                "offset: 0x160b4, size: 0x8a8, language -> ID: 1049, name -> ID: 1, type -> ID: RT_ICON",
                "offset: 0x1695c, size: 0x568, language -> ID: 1049, name -> ID: 2, type -> ID: RT_ICON",
                "offset: 0x16ec4, size: 0x2e8, language -> ID: 1049, name -> ID: 3, type -> ID: RT_ICON",
                "offset: 0x171ac, size: 0x128, language -> ID: 1049, name -> ID: 4, type -> ID: RT_ICON",
                "offset: 0x172d4, size: 0xd8, language -> ID: 1049, name -> LICENSEDLG, type -> ID: RT_DIALOG",
                "offset: 0x173ac, size: 0x12e, language -> ID: 1049, name -> RENAMEDLG, type -> ID: RT_DIALOG",
                "offset: 0x174dc, size: 0x338, language -> ID: 1049, name -> REPLACEFILEDLG, type -> ID: RT_DIALOG",
                "offset: 0x17814, size: 0x272, language -> ID: 1049, name -> STARTDLG, type -> ID: RT_DIALOG",
                "offset: 0x17a88, size: 0x22c, language -> ID: 1049, name -> ID: 7, type -> ID: RT_STRING",
                "offset: 0x17cb4, size: 0x376, language -> ID: 1049, name -> ID: 8, type -> ID: RT_STRING",
                "offset: 0x1802c, size: 0x200, language -> ID: 1049, name -> ID: 9, type -> ID: RT_STRING",
                "offset: 0x1822c, size: 0x10, language -> ID: 0, name -> DVCLAL, type -> ID: RT_RCDATA",
                "offset: 0x1823c, size: 0x3e, language -> ID: 1049, name -> ID: 100, type -> ID: RT_GROUP_ICON",
                "offset: 0x1827c, size: 0x331, language -> ID: 1049, name -> ID: 1, type -> ID: RT_MANIFEST" };
        PEData data = PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR
                + TestreportsReader.TEST_FILE_DIR + "/WinRar.exe"));
        SectionLoader loader = new SectionLoader(data);
        List<Resource> resources = loader.loadResourceSection().getResources();
        assertEquals(actResources.length, resources.size());
        for (int i = 0; i < actResources.length; i++) {
            assertEquals(actResources[i], resources.get(i).toString());
        }
    }

    @Test
    public void readResourceTypes() throws FileFormatException, IOException {
        for (TestData testdatum : testdata) {
            // this file can not be parsed correctly by pev
            if (testdatum.filename
                    .equals("VirusShare_05e261d74d06dd8d35583614def3f22e.txt"))
                continue;
            PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
            SectionLoader loader = new SectionLoader(pedatum);
            Optional<ResourceSection> rsrc = loader.maybeLoadResourceSection();
            if (rsrc.isPresent()) {
                List<Resource> resources = rsrc.get().getResources();
                for (Resource res : resources) {
                    String type = res.getType();
                    IDOrName id = res.getLevelIDs().get(Level.typeLevel());
                    if (!(testdatum.resTypes.contains(type) || id instanceof Name)) {
                        System.out.println("file: " + testdatum.filename);
                        System.out.println(res);
                        System.out.println("FAIL: searched for resource type "
                                + type);
                        System.out.println("in: ");
                        for (String str : testdatum.resTypes) {
                            System.out.println(str);
                        }
                    }
                    // TODO integrate name instance check, name entries are
                    // ignored by now
                    assertTrue(testdatum.resTypes.contains(type)
                            || id instanceof Name);
                }
            }
        }
    }
}
