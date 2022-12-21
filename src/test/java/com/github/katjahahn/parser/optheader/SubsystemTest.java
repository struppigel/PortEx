package com.github.katjahahn.parser.optheader;

import com.github.katjahahn.parser.coffheader.MachineType;
import org.testng.annotations.Test;

import java.io.IOException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class SubsystemTest {
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void noValidType() throws IOException {
        MachineType.getForValue(-1);
    }

    @Test
    public void validType() throws IOException {
        Subsystem subsystem = Subsystem.getForValue(1);
        assertEquals(subsystem, Subsystem.IMAGE_SUBSYSTEM_NATIVE);
        assertEquals(subsystem.getDescription(),
                "Device drivers and native Windows processes");
    }

    @Test
    public void coherence() {
        for (Subsystem subsystem : Subsystem.values()) {
            long value = subsystem.getValue();
            for (Subsystem compareTo : Subsystem.values()) {
                if (subsystem != compareTo) {
                    assertNotEquals(value, compareTo.getValue());
                }
            }
        }
    }
}
