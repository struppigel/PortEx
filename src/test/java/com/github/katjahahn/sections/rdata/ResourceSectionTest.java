package com.github.katjahahn.sections.rdata;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.PELoaderTest;
import com.github.katjahahn.TestreportsReader;
import com.github.katjahahn.TestreportsReader.TestData;
import com.github.katjahahn.parser.FileFormatException;
import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoader;
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
        String[] actResources = { "level: language -> ID: 0 || level: name -> ID: 101 || level: type -> ID: RT_RCDATA" };
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
    public void readWinRarResources() throws IOException {
        String[] actResources = {
                "level: language -> ID: 1049 || level: name ->  || level: type -> ID: RT_BITMAP",
                "level: language -> ID: 1049 || level: name -> ID: 1 || level: type -> ID: RT_ICON",
                "level: language -> ID: 1049 || level: name -> ID: 2 || level: type -> ID: RT_ICON",
                "level: language -> ID: 1049 || level: name -> ID: 3 || level: type -> ID: RT_ICON",
                "level: language -> ID: 1049 || level: name -> ID: 4 || level: type -> ID: RT_ICON",
                "level: language -> ID: 1049 || level: name ->  || level: type -> ID: RT_DIALOG",
                "level: language -> ID: 1049 || level: name ->  || level: type -> ID: RT_DIALOG",
                "level: language -> ID: 1049 || level: name ->  || level: type -> ID: RT_DIALOG",
                "level: language -> ID: 1049 || level: name ->  || level: type -> ID: RT_DIALOG",
                "level: language -> ID: 1049 || level: name -> ID: 7 || level: type -> ID: RT_STRING",
                "level: language -> ID: 1049 || level: name -> ID: 8 || level: type -> ID: RT_STRING",
                "level: language -> ID: 1049 || level: name -> ID: 9 || level: type -> ID: RT_STRING",
                "level: language -> ID: 0 || level: name ->  || level: type -> ID: RT_RCDATA",
                "level: language -> ID: 1049 || level: name -> ID: 100 || level: type -> ID: RT_GROUP_ICON",
                "level: language -> ID: 1049 || level: name -> ID: 1 || level: type -> ID: RT_MANIFEST" };
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
