package com.github.katjahahn.parser.sections;

import static org.testng.Assert.*;

import java.io.IOException;
import java.util.List;

import org.testng.annotations.Test;

public class SectionCharacteristicTest {
    @Test
    public void getAllSet() throws IOException {
        long value = 0xffffffff;
        List<SectionCharacteristic> list = SectionCharacteristic.getAllFor(value);
        assertEquals(list.size(), SectionCharacteristic.values().length);
    }

    @Test
    public void getNothing() throws IOException {
        long value = 0x00000000;
        List<SectionCharacteristic> list = SectionCharacteristic.getAllFor(value);
        assertEquals(list.size(), 0);
    }

    @Test
    public void getOne() throws IOException {
        long value = 0x00000020;
        List<SectionCharacteristic> list = SectionCharacteristic.getAllFor(value);
        assertEquals(list.size(), 1);
        assertEquals(list.get(0).getDescription(),
                "The section contains executable code.");
        assertEquals(list.get(0), SectionCharacteristic.IMAGE_SCN_CNT_CODE);
    }
}
