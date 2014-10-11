package com.github.katjahahn;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
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
    
    public static void main(String... args) {
        testAll();
    }

    public static void testAll() { //not a unit test, too costly
        File folder = new File(TestreportsReader.RESOURCE_DIR
                + "/badfiles/");
        List<String> fails = new ArrayList<>();
        int failed = 0;
        int counter = 0;
        for (File file : folder.listFiles()) {
            try {
                if(file.isDirectory()) {
                    System.err.println(file.getName());
                    continue;
                }
                counter++;
                if(counter % 100 == 0) {
                    System.out.println("Files read: " + counter);
                    System.out.println("Fails: " + failed);
                }
                PEData data = PELoader.loadPE(file);
//                new ReportCreator(data).headerReports();
                SectionLoader loader = new SectionLoader(data);
                
                loader.maybeLoadDebugSection();
                loader.maybeLoadDelayLoadSection();
//                loader.maybeLoadExceptionSection();
                loader.maybeLoadExportSection();
                loader.maybeLoadImportSection();
                loader.maybeLoadResourceSection();
                loader.maybeLoadRelocSection();
            } catch (Exception e) {
                String message = file.getName() + " " + e.getMessage();
                System.err.println(message);
                fails.add(message);
                failed++;
            }
        }
        System.out.println("Files that failed: " + failed);
        for(String message : fails) {
            System.out.println(message);
        }
    }

    @Test
    public void loadTinyPE() throws IOException {
        File tinyest = new File(PEAnomalyScannerTest.UNUSUAL_FOLDER
                + "/tinype/tinyest.exe");
        PEData data = PELoader.loadPE(tinyest);
        assertEquals(data.getSectionTable().getNumberOfSections(), 1);
        assertTrue(data.getOptionalHeader().getDataDirectory().isEmpty());

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
