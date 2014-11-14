package com.github.katjahahn.parser.coffheader;

import static org.testng.Assert.*;

import java.io.IOException;

import org.testng.annotations.Test;

public class MachineTypeTest {
    
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void noValidType() throws IOException {
        MachineType.getForValue(-1);
    }

    @Test
    public void validType() throws IOException {
        MachineType machine = MachineType.getForValue(0x1d3);
        assertEquals(machine, MachineType.AM33);
        assertEquals(machine.getDescription(), "Matsushita AM33");
    }

    @Test
    public void coherence() {
        for (MachineType machine : MachineType.values()) {
            long value = machine.getValue();
            for (MachineType compareTo : MachineType.values()) {
                if (machine != compareTo) {
                    assertNotEquals(value, compareTo.getValue());
                }
            }
        }
    }
}
