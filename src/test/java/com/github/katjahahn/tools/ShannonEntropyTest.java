package com.github.katjahahn.tools;

import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoaderTest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class ShannonEntropyTest {

    @SuppressWarnings("unused")
    private static final Logger logger = LogManager
            .getLogger(ShannonEntropyTest.class.getName());
    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void entropy() {
        byte[] bytes = new byte[10000];
        double entropy = ShannonEntropy.entropy(bytes);
        assertTrue(entropy == 0.0);
        Random rand = new Random();
        rand.nextBytes(bytes);
        entropy = ShannonEntropy.entropy(bytes);
        assertTrue(entropy > 0.9 && entropy <= 1.0);
    }

    @Test
    public void sectionEntropy() {
        for (PEData datum : pedata.values()) {
            ShannonEntropy entropy = new ShannonEntropy(datum);
            Map<Integer, Double> secEntropies = entropy.forSections();
            assertEquals(secEntropies.size(), datum.getSectionTable()
                    .getNumberOfSections());
            for (Double ent : secEntropies.values()) {
                assertTrue(ent >= 0.0 && ent <= 1.0);
            }
        }
    }

}
