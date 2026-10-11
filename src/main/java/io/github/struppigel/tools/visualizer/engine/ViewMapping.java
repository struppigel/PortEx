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

/**
 * Maps file offsets to cells of a grid and back.
 * <p>
 * The file is laid out row by row from a base offset. Each cell covers
 * {@link #getBytesPerCell()} bytes, each row {@link #getColumns()} cells. All
 * tracks of a visualization share one mapping; each track only chooses its own
 * cell width in pixels.
 * <p>
 * Instances are immutable. All offsets and row numbers are longs, so files of
 * any size can be mapped.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class ViewMapping {

    private final long fileLength;
    private final long baseOffset;
    private final long bytesPerCell;
    private final int columns;

    /**
     * Creates a mapping.
     *
     * @param fileLength the length of the file
     * @param baseOffset the file offset of the first cell, between 0 and the file length
     * @param bytesPerCell the number of bytes of a cell, at least 1
     * @param columns the number of cells per row, at least 1
     */
    public ViewMapping(long fileLength, long baseOffset, long bytesPerCell, int columns) {
        if (fileLength < 0 || baseOffset < 0 || baseOffset > fileLength) {
            throw new IllegalArgumentException("invalid base offset " + baseOffset + " for file length " + fileLength);
        }
        if (bytesPerCell < 1 || columns < 1) {
            throw new IllegalArgumentException("bytes per cell and columns must be positive");
        }
        if (bytesPerCell > Long.MAX_VALUE / columns) {
            throw new IllegalArgumentException("row size exceeds the long range");
        }
        this.fileLength = fileLength;
        this.baseOffset = baseOffset;
        this.bytesPerCell = bytesPerCell;
        this.columns = columns;
    }

    /**
     * Creates the mapping of the classic {@link io.github.struppigel.tools.visualizer.Visualizer}
     * images: {@code floor(fileWidth / pixelSize)} columns,
     * {@code ceil(height / pixelSize)} rows and
     * {@code ceil(fileLength / (columns * rows))} bytes per cell, at least 1.
     *
     * @param fileLength the length of the file
     * @param fileWidth the width of the image in pixels
     * @param height the height of the image in pixels
     * @param pixelSize the size of a cell in pixels
     * @return the mapping of the classic images
     */
    public static ViewMapping legacy(long fileLength, int fileWidth, int height, int pixelSize) {
        int columns = Math.max(1, (int) Math.floor(fileWidth / (double) pixelSize));
        long rows = legacyRows(height, pixelSize);
        long bytesPerCell = (long) Math.ceil(fileLength / (double) (columns * rows));
        return new ViewMapping(fileLength, 0, Math.max(1, bytesPerCell), columns);
    }

    /**
     * @param height the height of a classic image in pixels
     * @param pixelSize the size of a cell in pixels
     * @return the number of rows of a classic image, at least 1
     */
    public static int legacyRows(int height, int pixelSize) {
        return Math.max(1, (int) Math.ceil(height / (double) pixelSize));
    }

    /**
     * Returns the smallest number of bytes per cell that shows the file in at
     * most the given number of rows.
     *
     * @param fileLength the length of the file
     * @param columns the number of cells per row
     * @param rows the maximum number of rows
     * @param powerOfTwo true to round up to a power of two, which aligns cells
     *            with the blocks of {@link ByteStatistics}
     * @return the bytes per cell, at least 1
     */
    public static long fitBytesPerCell(long fileLength, int columns, long rows, boolean powerOfTwo) {
        if (columns < 1 || rows < 1) {
            throw new IllegalArgumentException("columns and rows must be positive");
        }
        long cells = columns * rows;
        long bytesPerCell = Math.max(1, (fileLength + cells - 1) / cells);
        if (powerOfTwo) {
            long p = 1;
            while (p < bytesPerCell) {
                p <<= 1;
            }
            bytesPerCell = p;
        }
        return bytesPerCell;
    }

    /**
     * @return the length of the mapped file
     */
    public long getFileLength() {
        return fileLength;
    }

    /**
     * @return the file offset of the first cell
     */
    public long getBaseOffset() {
        return baseOffset;
    }

    /**
     * @return the number of bytes of a cell
     */
    public long getBytesPerCell() {
        return bytesPerCell;
    }

    /**
     * @return the number of cells per row
     */
    public int getColumns() {
        return columns;
    }

    /**
     * @return the number of bytes of a row
     */
    public long getBytesPerRow() {
        return bytesPerCell * columns;
    }

    /**
     * @return the number of rows needed to show the file from the base offset
     */
    public long getRowCount() {
        long bytes = fileLength - baseOffset;
        long perRow = getBytesPerRow();
        return bytes / perRow + (bytes % perRow == 0 ? 0 : 1);
    }

    /**
     * Returns the row of an offset. Offsets before the base offset have
     * negative rows.
     *
     * @param offset the file offset
     * @return the row
     */
    public long rowOf(long offset) {
        return Math.floorDiv(offset - baseOffset, getBytesPerRow());
    }

    /**
     * @param offset the file offset
     * @return the column of the offset
     */
    public int columnOf(long offset) {
        return (int) (Math.floorMod(offset - baseOffset, getBytesPerRow()) / bytesPerCell);
    }

    /**
     * Returns the start offset of a cell, clipped to the file length.
     *
     * @param row the row
     * @param column the column
     * @return the first offset of the cell
     */
    public long cellStart(long row, int column) {
        long start = baseOffset + row * getBytesPerRow() + column * bytesPerCell;
        return Math.min(Math.max(start, 0), fileLength);
    }

    /**
     * Returns the end offset of a cell (exclusive), clipped to the file length.
     * The last cell of the file can be shorter than the others.
     *
     * @param row the row
     * @param column the column
     * @return the offset after the last byte of the cell
     */
    public long cellEnd(long row, int column) {
        long end = baseOffset + row * getBytesPerRow() + (column + 1L) * bytesPerCell;
        return Math.min(Math.max(end, 0), fileLength);
    }

    /**
     * @param bytesPerCell the new bytes per cell
     * @return a mapping with the same base offset and columns
     */
    public ViewMapping withBytesPerCell(long bytesPerCell) {
        return new ViewMapping(fileLength, baseOffset, bytesPerCell, columns);
    }

    /**
     * @param columns the new number of columns
     * @return a mapping with the same base offset and bytes per cell
     */
    public ViewMapping withColumns(int columns) {
        return new ViewMapping(fileLength, baseOffset, bytesPerCell, columns);
    }

    /**
     * @param baseOffset the new base offset
     * @return a mapping with the same bytes per cell and columns
     */
    public ViewMapping withBaseOffset(long baseOffset) {
        return new ViewMapping(fileLength, baseOffset, bytesPerCell, columns);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ViewMapping)) return false;
        ViewMapping that = (ViewMapping) o;
        return fileLength == that.fileLength && baseOffset == that.baseOffset
                && bytesPerCell == that.bytesPerCell && columns == that.columns;
    }

    @Override
    public int hashCode() {
        int h = Long.hashCode(fileLength);
        h = 31 * h + Long.hashCode(baseOffset);
        h = 31 * h + Long.hashCode(bytesPerCell);
        return 31 * h + columns;
    }

    @Override
    public String toString() {
        return "ViewMapping[length=" + fileLength + ", base=0x" + Long.toHexString(baseOffset) + ", bytesPerCell="
                + bytesPerCell + ", columns=" + columns + "]";
    }
}
