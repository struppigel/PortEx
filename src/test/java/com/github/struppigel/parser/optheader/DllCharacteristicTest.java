package com.github.struppigel.parser.optheader;

import org.testng.annotations.Test;

import java.io.IOException;
import java.util.List;

import static org.testng.Assert.assertEquals;

public class DllCharacteristicTest {
    @Test
    public void getAllSet() throws IOException {
        long value = 0xffffffff;
        List<DllCharacteristic> list = DllCharacteristic.getAllFor(value);
        assertEquals(list.size(), DllCharacteristic.values().length);
    }

    @Test
    public void getNothing() throws IOException {
        long value = 0x00000000;
        List<DllCharacteristic> list = DllCharacteristic.getAllFor(value);
        assertEquals(list.size(), 0);
    }

    @Test
    public void getOne() throws IOException {
        long value = 0x100;
        List<DllCharacteristic> list = DllCharacteristic.getAllFor(value);
        assertEquals(list.size(), 1);
        assertEquals(list.get(0).getDescription(),
                "Image is NX compatible.");
        assertEquals(list.get(0), DllCharacteristic.IMAGE_DLLCHARACTERISTICS_NX_COMPAT);
    }
}
