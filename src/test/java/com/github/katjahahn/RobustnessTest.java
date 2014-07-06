package com.github.katjahahn;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.List;

import org.testng.annotations.Test;

import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoader;
import com.github.katjahahn.parser.sections.SectionLoader;
import com.github.katjahahn.parser.sections.idata.ImportDLL;
import com.github.katjahahn.tools.anomalies.PEAnomalyScannerTest;

public class RobustnessTest {

    public static final String PROBLEMFILES_DIR = TestreportsReader.RESOURCE_DIR
            + "/problemfiles/";

    @Test
    public void loadTinyPE() throws IOException {
        File tinyest = new File(PEAnomalyScannerTest.UNUSUAL_FOLDER
                + "/tinype/tinyest.exe");
        PEData data = PELoader.loadPE(tinyest);
        assertEquals(data.getSectionTable().getNumberOfSections(), 1);
        assertTrue(data.getOptionalHeader().getDataDirEntries().isEmpty());

        File downloader = new File(PEAnomalyScannerTest.UNUSUAL_FOLDER
                + "/tinype/downloader.exe");
        data = PELoader.loadPE(downloader);
        List<ImportDLL> imports = new SectionLoader(data).loadImportSection()
                .getImports();
        assertFalse(imports.isEmpty());
        assertTrue(imports.get(0).getName().equals("KERNEL32.dll"));
    }

    @Test
    public void loadProblemfiles() throws IOException {
        File folder = new File(PROBLEMFILES_DIR);
        for (File file : folder.listFiles()) {
            PEData data = PELoader.loadPE(file);
            SectionLoader loader = new SectionLoader(data);
            loader.maybeLoadDebugSection();
            loader.maybeLoadExceptionSection();
            loader.maybeLoadImportSection();
            loader.maybeLoadResourceSection();
        }
    }

}
