package com.github.katjahahn.parser.coffheader;

import static org.testng.Assert.*;

import java.io.IOException;
import java.util.List;

import org.testng.annotations.Test;

public class FileCharacteristicTest {
    @Test
    public void getAllSet() throws IOException {
        long value = 0xffffffff;
        List<FileCharacteristic> list = FileCharacteristic.getAllFor(value);
        assertEquals(list.size(), FileCharacteristic.values().length);
    }
}
