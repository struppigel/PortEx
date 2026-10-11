/*******************************************************************************
 * Copyright 2026 Karsten Philipp Boris Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package io.github.struppigel.tools.visualizer.engine;

import org.testng.annotations.Test;

import java.awt.Point;
import java.util.Random;

import static org.testng.Assert.*;

public class ViewMappingTest {

    @Test
    public void offsetCellRoundTrip() {
        Random random = new Random(1);
        for (int i = 0; i < 200; i++) {
            long length = 1 + random.nextInt(1 << 24);
            long base = random.nextInt((int) Math.min(length, 1 << 12));
            ViewMapping mapping = new ViewMapping(length, base, 1 + random.nextInt(5000), 1 + random.nextInt(128));
            for (int k = 0; k < 50; k++) {
                long offset = base + (long) (random.nextDouble() * (length - base));
                long row = mapping.rowOf(offset);
                int column = mapping.columnOf(offset);
                assertTrue(row >= 0 && row < mapping.getRowCount());
                assertTrue(column >= 0 && column < mapping.getColumns());
                long start = mapping.cellStart(row, column);
                long end = mapping.cellEnd(row, column);
                assertTrue(start <= offset && offset < end, mapping + " offset " + offset);
                assertTrue(end - start <= mapping.getBytesPerCell());
            }
        }
    }

    @Test
    public void lastCellIsClipped() {
        ViewMapping mapping = new ViewMapping(1000, 0, 64, 4);
        assertEquals(mapping.getBytesPerRow(), 256);
        assertEquals(mapping.getRowCount(), 4);
        // offset 999 is in cell 15 = row 3, column 3, which ends at the file end
        assertEquals(mapping.rowOf(999), 3);
        assertEquals(mapping.columnOf(999), 3);
        assertEquals(mapping.cellStart(3, 3), 960);
        assertEquals(mapping.cellEnd(3, 3), 1000);
        // cells after the end are empty
        assertEquals(mapping.cellStart(4, 0), 1000);
        assertEquals(mapping.cellEnd(4, 0), 1000);
    }

    @Test
    public void baseOffsetShiftsTheGrid() {
        ViewMapping mapping = new ViewMapping(1000, 100, 10, 10);
        assertEquals(mapping.getRowCount(), 9);
        assertEquals(mapping.rowOf(100), 0);
        assertEquals(mapping.rowOf(99), -1);
        assertEquals(mapping.cellStart(0, 0), 100);
        assertEquals(mapping.columnOf(155), 5);
    }

    @Test
    public void hugeFilesDoNotOverflow() {
        long length = (1L << 40) + 12345;
        ViewMapping mapping = new ViewMapping(length, 0, 1, 64);
        long offset = length - 1;
        long row = mapping.rowOf(offset);
        assertEquals(row, offset / 64);
        assertEquals(mapping.cellStart(row, mapping.columnOf(offset)), offset);
        assertEquals(mapping.getRowCount(), (length + 63) / 64);
        Viewport viewport = new Viewport(mapping, row - 10, 20, 14);
        assertTrue(viewport.isVisible(offset));
        Point p = viewport.pixelOf(offset, 20);
        assertEquals(viewport.offsetAt(p.x, p.y, 20), offset);
        // far away rows saturate instead of overflowing
        Point far = new Viewport(mapping, 0, 20, 14).pixelOf(offset, 20);
        assertEquals(far.y, Integer.MAX_VALUE);
    }

    /** the formulas of the classic Visualizer */
    private static long legacyBytesPerPixel(long fileSize, int fileWidth, int height, int pixelSize) {
        int xPixels = (int) Math.floor(fileWidth / (double) pixelSize);
        int yPixels = (int) Math.ceil(height / (double) pixelSize);
        return (int) Math.ceil(fileSize / (double) (xPixels * (long) yPixels));
    }

    @Test
    public void legacyMatchesTheOldFormula() {
        int[][] settings = {{300, 600, 5}, {256, 1000, 4}, {256, 37, 1}, {600, 800, 10}, {180, 500, 5},
                {50, 333, 3}, {301, 599, 7}};
        long[] lengths = {1, 4608, 1200490, 72_000_000L, 999, 5_000_000_000L};
        for (int[] s : settings) {
            for (long length : lengths) {
                ViewMapping mapping = ViewMapping.legacy(length, s[0], s[1], s[2]);
                long bpp = Math.max(1, legacyBytesPerPixel(length, s[0], s[1], s[2]));
                int xPixels = (int) Math.floor(s[0] / (double) s[2]);
                assertEquals(mapping.getBytesPerCell(), bpp);
                assertEquals(mapping.getColumns(), xPixels);
                assertEquals(ViewMapping.legacyRows(s[1], s[2]), (int) Math.ceil(s[1] / (double) s[2]));
                // old getPixelNumber(offset) = offset / bytesPerPixel, drawn at (i % x, i / x)
                Random random = new Random(length);
                for (int i = 0; i < 100; i++) {
                    long offset = (long) (random.nextDouble() * length);
                    long pixel = offset / bpp;
                    assertEquals(mapping.rowOf(offset), pixel / xPixels);
                    assertEquals(mapping.columnOf(offset), pixel % xPixels);
                }
            }
        }
    }

    @Test
    public void fitBytesPerCell() {
        assertEquals(ViewMapping.fitBytesPerCell(0, 64, 100, false), 1);
        assertEquals(ViewMapping.fitBytesPerCell(6400, 64, 100, false), 1);
        assertEquals(ViewMapping.fitBytesPerCell(6401, 64, 100, false), 2);
        assertEquals(ViewMapping.fitBytesPerCell(6401 * 3, 64, 100, true), 4);
        long length = 70_000_000;
        long bpc = ViewMapping.fitBytesPerCell(length, 64, 1000, true);
        assertEquals(Long.bitCount(bpc), 1);
        assertTrue(new ViewMapping(length, 0, bpc, 64).getRowCount() <= 1000);
        assertTrue(new ViewMapping(length, 0, bpc / 2, 64).getRowCount() > 1000);
    }

    @Test
    public void pixelOffsetRoundTrip() {
        ViewMapping mapping = new ViewMapping(100_000, 0, 16, 64);
        Viewport viewport = new Viewport(mapping, 20, 50, 4);
        Random random = new Random(2);
        for (int i = 0; i < 1000; i++) {
            long offset = viewport.getStartOffset() + random.nextInt((int) (viewport.getEndOffset() - viewport.getStartOffset()));
            Point p = viewport.pixelOf(offset, 3);
            long cellStart = viewport.offsetAt(p.x, p.y, 3);
            assertEquals(cellStart, offset - offset % 16);
            // all pixels of the cell map to the cell
            assertEquals(viewport.offsetAt(p.x + 2, p.y + 3, 3), cellStart);
        }
        assertEquals(viewport.offsetAt(-1, 0, 3), -1);
        assertEquals(viewport.offsetAt(64 * 3, 0, 3), -1);
        assertEquals(viewport.offsetAt(0, 50 * 4, 3), -1);
        assertEquals(viewport.offsetAt(0, 0, 3), 20 * 1024);
    }

    @Test
    public void offsetsAfterTheEndAreNotOnACell() {
        ViewMapping mapping = new ViewMapping(1000, 0, 64, 4);
        Viewport viewport = new Viewport(mapping, 0, 10, 4);
        assertEquals(viewport.offsetAt(3 * 4, 3 * 4, 4), 960);
        assertEquals(viewport.offsetAt(0, 4 * 4, 4), -1);
        assertFalse(viewport.isVisible(1000));
    }

    @Test
    public void zoomKeepsTheAnchorRow() {
        ViewMapping mapping = new ViewMapping(10_000_000, 0, 1024, 64);
        Viewport viewport = new Viewport(mapping, 50, 100, 4);
        long anchor = mapping.cellStart(80, 10) + 77;
        int screenRow = (int) (mapping.rowOf(anchor) - viewport.getFirstRow());
        for (long bpc : new long[]{512, 256, 16, 1, 2048, 1024}) {
            Viewport zoomed = viewport.zoomAround(anchor, screenRow, bpc);
            assertEquals(zoomed.getMapping().getBytesPerCell(), bpc);
            assertEquals(zoomed.getMapping().rowOf(anchor) - zoomed.getFirstRow(), screenRow);
            assertTrue(zoomed.isVisible(anchor));
        }
        // the first row does not become negative
        Viewport top = viewport.zoomAround(100, 50, 4096);
        assertEquals(top.getFirstRow(), 0);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void invalidMapping() {
        new ViewMapping(100, 200, 1, 1);
    }
}
