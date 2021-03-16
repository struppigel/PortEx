package com.github.katjahahn.parser.sections.reloc;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoaderTest;
import com.github.katjahahn.parser.sections.SectionLoader;

public class RelocationSectionTest {

    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void relocsNumber() throws IOException {
        String[] relocArr = {
                "portextestfiles/testfiles/Lab03-02;6;890",
                "portextestfiles/testfiles/Lab11-02dll;1;100",
                "portextestfiles/testfiles/Lab07-03;1;46",
                "portextestfiles/testfiles/Lab17-02dll;24;3016",
                "portextestfiles/testfiles/Lab11-03dll;9;766",
                "portextestfiles/testfiles/Lab05-01;24;3016",
                "portextestfiles/testfiles/Lab12-01dll;9;738",
                "portextestfiles/testfiles/Lab18-04;1;0"
        };
        for (String rel : relocArr) {
            System.out.println(rel);
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
