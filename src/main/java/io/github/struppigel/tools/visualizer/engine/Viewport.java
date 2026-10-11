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

import java.awt.Point;

/**
 * A range of rows of a {@link ViewMapping} shown on screen.
 * <p>
 * The viewport converts between pixels and file offsets. Pixel coordinates are
 * relative to the top left corner of the first shown row. Rows are
 * {@link #getCellHeight()} pixels high; the width of a cell depends on the
 * track and is passed to the methods.
 * <p>
 * Instances are immutable.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class Viewport {

    private final ViewMapping mapping;
    private final long firstRow;
    private final int rowCount;
    private final int cellHeight;

    /**
     * Creates a viewport.
     *
     * @param mapping the mapping
     * @param firstRow the first shown row, at least 0
     * @param rowCount the number of shown rows, at least 0
     * @param cellHeight the height of a row in pixels, at least 1
     */
    public Viewport(ViewMapping mapping, long firstRow, int rowCount, int cellHeight) {
        if (firstRow < 0 || rowCount < 0 || cellHeight < 1) {
            throw new IllegalArgumentException("invalid viewport rows " + firstRow + "+" + rowCount
                    + " or cell height " + cellHeight);
        }
        this.mapping = mapping;
        this.firstRow = firstRow;
        this.rowCount = rowCount;
        this.cellHeight = cellHeight;
    }

    /**
     * @return the mapping
     */
    public ViewMapping getMapping() {
        return mapping;
    }

    /**
     * @return the first shown row
     */
    public long getFirstRow() {
        return firstRow;
    }

    /**
     * @return the number of shown rows
     */
    public int getRowCount() {
        return rowCount;
    }

    /**
     * @return the row after the last shown row
     */
    public long getEndRow() {
        return firstRow + rowCount;
    }

    /**
     * @return the height of a row in pixels
     */
    public int getCellHeight() {
        return cellHeight;
    }

    /**
     * @return the file offset of the first shown cell, clipped to the file
     */
    public long getStartOffset() {
        return mapping.cellStart(firstRow, 0);
    }

    /**
     * @return the offset after the last shown cell, clipped to the file
     */
    public long getEndOffset() {
        return mapping.cellStart(getEndRow(), 0);
    }

    /**
     * Returns the first offset of the cell at a pixel.
     *
     * @param x the x coordinate in pixels
     * @param y the y coordinate in pixels, 0 is the top of the first shown row
     * @param cellWidth the width of a cell of the track in pixels
     * @return the first offset of the cell, -1 if the pixel is not on a cell
     *         of the file
     */
    public long offsetAt(int x, int y, int cellWidth) {
        if (x < 0 || y < 0 || cellWidth < 1) {
            return -1;
        }
        int column = x / cellWidth;
        int rowInView = y / cellHeight;
        if (column >= mapping.getColumns() || rowInView >= rowCount) {
            return -1;
        }
        long row = firstRow + rowInView;
        long offset = mapping.getBaseOffset() + row * mapping.getBytesPerRow() + column * mapping.getBytesPerCell();
        return offset < mapping.getFileLength() ? offset : -1;
    }

    /**
     * Returns the top left pixel of the cell that contains the offset. The
     * pixel may lie outside of the viewport; y is saturated to the int range.
     *
     * @param offset the file offset
     * @param cellWidth the width of a cell of the track in pixels
     * @return the top left pixel of the cell
     */
    public Point pixelOf(long offset, int cellWidth) {
        long row = mapping.rowOf(offset) - firstRow;
        long y = row * cellHeight;
        int yInt = (int) Math.max(Integer.MIN_VALUE, Math.min(Integer.MAX_VALUE, y));
        return new Point(mapping.columnOf(offset) * cellWidth, yInt);
    }

    /**
     * @param offset the file offset
     * @return true if the row of the offset is shown
     */
    public boolean isVisible(long offset) {
        long row = mapping.rowOf(offset);
        return row >= firstRow && row < getEndRow() && offset >= mapping.getBaseOffset()
                && offset < mapping.getFileLength();
    }

    /**
     * Changes the bytes per cell and keeps the anchor offset on the same row
     * of the screen, as far as the first row stays at least 0.
     *
     * @param anchorOffset the offset to keep in place, e.g. under the mouse
     * @param anchorScreenRow the row of the screen the anchor is shown in
     * @param newBytesPerCell the new bytes per cell
     * @return the zoomed viewport
     */
    public Viewport zoomAround(long anchorOffset, int anchorScreenRow, long newBytesPerCell) {
        ViewMapping zoomed = mapping.withBytesPerCell(newBytesPerCell);
        long newFirstRow = Math.max(0, zoomed.rowOf(anchorOffset) - anchorScreenRow);
        return new Viewport(zoomed, newFirstRow, rowCount, cellHeight);
    }

    /**
     * @param newFirstRow the new first row
     * @return a viewport that shows the same number of rows from the new first row
     */
    public Viewport withFirstRow(long newFirstRow) {
        return new Viewport(mapping, newFirstRow, rowCount, cellHeight);
    }

    /**
     * @param newRowCount the new number of rows
     * @return a viewport with the same first row
     */
    public Viewport withRowCount(int newRowCount) {
        return new Viewport(mapping, firstRow, newRowCount, cellHeight);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Viewport)) return false;
        Viewport that = (Viewport) o;
        return firstRow == that.firstRow && rowCount == that.rowCount && cellHeight == that.cellHeight
                && mapping.equals(that.mapping);
    }

    @Override
    public int hashCode() {
        int h = mapping.hashCode();
        h = 31 * h + Long.hashCode(firstRow);
        h = 31 * h + rowCount;
        return 31 * h + cellHeight;
    }

    @Override
    public String toString() {
        return "Viewport[" + mapping + ", rows " + firstRow + "+" + rowCount + ", cellHeight=" + cellHeight + "]";
    }
}
