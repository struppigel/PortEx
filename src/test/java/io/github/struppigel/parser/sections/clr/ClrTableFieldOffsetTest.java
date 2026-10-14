package io.github.struppigel.parser.sections.clr;

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.StandardField;
import io.github.struppigel.parser.sections.SectionLoader;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class ClrTableFieldOffsetTest {

    private static final String DIR = TestreportsReader.RESOURCE_DIR + "/testfiles/";

    @Test
    public void fieldsOfEveryRowStartAtTheOffsetOfTheRow() throws IOException {
        for (String name : new String[]{"HelloWorld.exe", "NetCoreConsole.dll"}) {
            OptimizedStream stream = new SectionLoader(PELoader.loadPE(new File(DIR + name))).loadCLRSection()
                    .getMetadataRoot().maybeGetOptimizedStream().get();
            int rowsChecked = 0;
            for (CLRTable table : stream.getCLRTables()) {
                long previousEnd = 0;
                for (CLRTableEntry entry : table.getEntries()) {
                    long first = Long.MAX_VALUE;
                    long end = 0;
                    for (StandardField field : entry.getCLRFieldsAsStandardFields()) {
                        first = Math.min(first, field.getOffset());
                        end = Math.max(end, field.getOffset() + field.getSize());
                    }
                    assertEquals(first, entry.rawOffset(), name + " " + table.getTableName() + " row " + entry.row());
                    assertTrue(first >= previousEnd, name + " " + table.getTableName() + " row " + entry.row());
                    previousEnd = end;
                    rowsChecked++;
                }
            }
            assertTrue(rowsChecked > 2, name);
        }
    }
}
