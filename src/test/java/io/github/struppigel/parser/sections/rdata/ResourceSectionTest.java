package io.github.struppigel.parser.sections.rdata;

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.TestreportsReader.TestData;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.PELoaderTest;
import io.github.struppigel.parser.sections.SectionLoader;
import io.github.struppigel.parser.sections.rsrc.Resource;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;

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
        String[] actResources = { "offset: 0x3a0, size: 0x22, language -> ID: 0, name -> ID: 29524, type -> ID: 789" };
        PEData data = PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR
                + "/corkami/resourceloop.exe"));
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
                + "/corkami/resource_shuffled.exe"));
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
}
