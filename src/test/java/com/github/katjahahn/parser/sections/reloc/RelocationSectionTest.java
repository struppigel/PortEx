package com.github.katjahahn.parser.sections.reloc;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoaderTest;
import com.github.katjahahn.parser.sections.SectionLoader;

public class RelocationSectionTest {

    private static final Logger logger = LogManager
            .getLogger(RelocationSectionTest.class.getName());
    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void relocsNumber() throws IOException {
        String[] relocArr = {
                "/home/deque/portextestfiles/testfiles/Lab03-02.dll;6;890",
                "/home/deque/portextestfiles/testfiles/DLL1.dll;9;740",
                "/home/deque/portextestfiles/testfiles/Lab11-02.dll;1;100",
                "/home/deque/portextestfiles/testfiles/ntdll.dll;165;8534",
                "/home/deque/portextestfiles/testfiles/DLL2.dll;9;742",
                "/home/deque/portextestfiles/testfiles/Lab07-03.dll;1;46",
                "/home/deque/portextestfiles/testfiles/Lab17-02.dll;24;3016",
                "/home/deque/portextestfiles/testfiles/Lab11-03.dll;9;766",
                "/home/deque/portextestfiles/testfiles/Lab05-01.dll;24;3016",
                "/home/deque/portextestfiles/testfiles/Lab12-01.dll;9;738",
                "/home/deque/portextestfiles/testfiles/Lab18-04.exe;1;0",
                "/home/deque/portextestfiles/testfiles/DLL3.dll;9;748" };
        for (String rel : relocArr) {
            String[] split = rel.split(";");
            File file = new File(split[0]);
            int blockNr = Integer.parseInt(split[1]);
            int entryNr = Integer.parseInt(split[2]);
            PEData data = pedata.get(file.getName());
            SectionLoader loader = new SectionLoader(data);
            RelocationSection reloc = loader.loadRelocSection();
            assertEquals(blockNr, reloc.getRelocBlocks().size());
            int entrySum = 0;
            for (BaseRelocBlock block : reloc.getRelocBlocks()) {
                entrySum += block.entries().size();
            }
            assertEquals(entryNr, entrySum);
        }
    }
}
