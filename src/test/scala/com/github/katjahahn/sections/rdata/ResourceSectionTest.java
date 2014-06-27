package com.github.katjahahn.sections.rdata;

import static org.testng.Assert.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.PELoaderTest;
import com.github.katjahahn.TestreportsReader.TestData;
import com.github.katjahahn.parser.FileFormatException;
import com.github.katjahahn.parser.PEData;
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
    public void readResourceTypes() throws FileFormatException, IOException {
        for (TestData testdatum : testdata) {
            PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
            SectionLoader loader = new SectionLoader(pedatum);
            Optional<ResourceSection> rsrc = loader.maybeLoadResourceSection();
            if (rsrc.isPresent()) {
                List<Resource> resources = rsrc.get().getResources();
                for (Resource res : resources) {
                    String type = res.getType();
                    IDOrName id = res.getLevelIDs().get(Level.typeLevel());
                    if (!testdatum.resTypes.contains(type) || id instanceof Name) {
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
