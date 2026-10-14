package io.github.struppigel.tools.anomalies;

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.PhysicalLocation;
import io.github.struppigel.parser.sections.SectionHeader;
import io.github.struppigel.parser.sections.SectionHeaderKey;
import io.github.struppigel.parser.sections.SectionTable;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;

/** The section name anomalies have to mark the name field of their own section header. */
public class SectionNameAnomalyTest {

    private static final File FILE = new File(TestreportsReader.RESOURCE_DIR + "/testfiles/DotNetBundle.exe");
    private static final int ENTRY_SIZE = 40;
    private static final int NAME_SIZE = 8;

    @Test
    public void fieldsOfEverySectionHeaderAreAtTheOffsetOfTheHeader() throws IOException {
        PEData data = PELoader.loadPE(FILE);
        SectionTable table = data.getSectionTable();
        for (SectionHeader header : table.getSectionHeaders()) {
            long expected = table.getOffset() + (long) (header.getNumber() - 1) * ENTRY_SIZE;
            assertEquals(header.getField(SectionHeaderKey.NAME).getOffset(), expected, "section " + header.getNumber());
            assertEquals(header.getNameOffset(), expected, "section " + header.getNumber());
        }
    }

    @Test
    public void unusualSectionNameMarksTheNameOfThatSection() throws IOException {
        PEData data = PELoader.loadPE(FILE);
        SectionTable table = data.getSectionTable();
        int found = 0;
        for (Anomaly anomaly : PEAnomalyScanner.newInstance(data).getAnomalies()) {
            if (anomaly.subtype() != AnomalySubType.UNUSUAL_SEC_NAME) {
                continue;
            }
            found++;
            SectionNameAnomaly sectionName = (SectionNameAnomaly) anomaly;
            long expected = table.getOffset() + (long) (sectionName.header().getNumber() - 1) * ENTRY_SIZE;
            List<PhysicalLocation> locations = anomaly.locations();
            assertEquals(locations.size(), 1);
            assertEquals(locations.get(0).from(), expected, anomaly.description());
            assertEquals(locations.get(0).size(), NAME_SIZE, anomaly.description());
        }
        assertFalse(found == 0, "DotNetBundle.exe has an unusual section name");
    }
}
