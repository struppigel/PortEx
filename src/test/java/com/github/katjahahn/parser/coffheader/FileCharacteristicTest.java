package com.github.katjahahn.parser.coffheader;

import org.testng.annotations.Test;

import java.io.IOException;
import java.util.List;

import static org.testng.Assert.assertEquals;

public class FileCharacteristicTest {
    @Test
    public void getAllSet() throws IOException {
        long value = 0xffffffff;
        List<FileCharacteristic> list = FileCharacteristic.getAllFor(value);
        assertEquals(list.size(), FileCharacteristic.values().length);
    }

    @Test
    public void getNothing() throws IOException {
        long value = 0x00000000;
        List<FileCharacteristic> list = FileCharacteristic.getAllFor(value);
        assertEquals(list.size(), 0);
    }

    @Test
    public void getOne() throws IOException {
        long value = 0x00000001;
        List<FileCharacteristic> list = FileCharacteristic.getAllFor(value);
        assertEquals(list.size(), 1);
        assertEquals(list.get(0).getDescription(),
                "Image only, Windows CE, and Windows NT and later.");
        assertEquals(list.get(0), FileCharacteristic.IMAGE_FILE_RELOCS_STRIPPED);
    }
}
