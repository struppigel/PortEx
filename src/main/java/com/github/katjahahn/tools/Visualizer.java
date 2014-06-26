/*******************************************************************************
 * Copyright 2014 Katja Hahn
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
package com.github.katjahahn.tools;

import java.awt.Color;
import java.awt.Graphics;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import javax.imageio.ImageIO;
import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;

import com.github.katjahahn.parser.Location;
import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoader;
import com.github.katjahahn.parser.coffheader.COFFFileHeader;
import com.github.katjahahn.parser.optheader.StandardFieldEntryKey;
import com.github.katjahahn.parser.sections.SectionHeader;
import com.github.katjahahn.parser.sections.SectionHeaderKey;
import com.github.katjahahn.parser.sections.SectionLoader;
import com.github.katjahahn.parser.sections.SectionTable;
import com.github.katjahahn.parser.sections.debug.DebugSection;
import com.github.katjahahn.parser.sections.edata.ExportSection;
import com.github.katjahahn.parser.sections.idata.ImportSection;
import com.github.katjahahn.parser.sections.rsrc.ResourceSection;
import com.github.katjahahn.tools.anomalies.PEAnomalyScanner;
import com.google.common.base.Optional;
import com.google.java.contract.Ensures;
import com.google.java.contract.Requires;

/**
 * Creates an image that represents the structure of your PE file.
 * 
 * @author Katja Hahn
 * 
 */
public class Visualizer {
    // TODO make with work with tinype and duplicated sections

    /**
     * The default width of the file shown is {@value}
     */
    public static final int DEFAULT_FILE_WIDTH = 300;
    /**
     * The default image and file height is {@value}
     */
    public static final int DEFAULT_HEIGHT = 600;
    /**
     * The default size of one pixel-block in the image is {@value}
     */
    public static final int DEFAULT_PIXEL_SIZE = 5;
    /**
     * The default width of the legend is {@value}
     */
    public static final int DEFAULT_LEGEND_WIDTH = 200;
    /**
     * The default of the reduced size on each side of pixels that lie on top of
     * others. Imagine it like a transparent border. Value is {@value}
     */
    public static final int DEFAULT_ADDITIONAL_GAP = 1;
    /**
     * The default for pixelating the image is {@value} .
     * <p>
     * A pixelated image will have borders for every pixel-block.
     */
    public static final boolean DEFAULT_PIXELATED = false;

    private static final int IMAGE_TYPE = BufferedImage.TYPE_INT_RGB;
    private static final int LEGEND_SAMPLE_SIZE = 10;
    private static final int LEGEND_GAP = 10;
    private static final int LEGEND_ENTRY_HEIGHT = 20;

    private int additionalGap;
    private int pixelSize;
    private boolean pixelated;
    private int fileWidth;
    private int height;
    private int legendWidth;
    private final Color msdosColor = new Color(0, 0, 200);
    private final Color coffColor = new Color(0, 200, 0);
    private final Color optColor = new Color(200, 0, 0);
    private final Color sectionTableColor = new Color(200, 200, 0);
    private final Color sectionColorStart = new Color(220, 220, 220);
    private final Color overlayColor = new Color(100, 100, 240);
    private final Color importColor = new Color(250, 250, 80);
    private final Color exportColor = new Color(220, 80, 220);
    private final Color rsrcColor = new Color(100, 250, 100);
    private final Color debugColor = new Color(0, 0, 220);
    private final Color epColor = new Color(255, 80, 80);
    private final PEData data;
    private BufferedImage image;

    private boolean importsAvailable;
    private boolean exportsAvailable;
    private boolean resourcesAvailable;
    private boolean debugAvailable;
    private boolean overlayAvailable;
    private boolean epAvailable;

    /**
     * Visualizer instance with default values applied.
     * <p>
     * Default values are:
     * <ul>
     * <li>{@link Visualizer#DEFAULT_PIXEL_SIZE}</li>
     * <li>{@link Visualizer#DEFAULT_PIXELATED}</li>
     * <li>{@link Visualizer#DEFAULT_ADDITIONAL_GAP}</li>
     * <li>{@link Visualizer#DEFAULT_HEIGHT}</li>
     * <li>{@link Visualizer#DEFAULT_FILE_WIDTH}</li>
     * <li>{@link Visualizer#DEFAULT_LEGEND_WIDTH}</li>
     * </ul>
     * 
     * @param data
     *            the data object of the PE file to visualize
     */
    public Visualizer(PEData data) {
        this(data, DEFAULT_PIXEL_SIZE);
    }

    /**
     * Visualizer instance with pixelSize and otherwise default values applied.
     * <p>
     * Default values are:
     * <ul>
     * <li>{@link Visualizer#DEFAULT_PIXELATED}</li>
     * <li>{@link Visualizer#DEFAULT_ADDITIONAL_GAP}</li>
     * <li>{@link Visualizer#DEFAULT_HEIGHT}</li>
     * <li>{@link Visualizer#DEFAULT_FILE_WIDTH}</li>
     * <li>{@link Visualizer#DEFAULT_LEGEND_WIDTH}</li>
     * </ul>
     * 
     * @param data
     *            the data object of the PE file to visualize
     * @param pixelSize
     *            size of one rectangle that represents a certain amount of
     *            bytes
     */
    public Visualizer(PEData data, int pixelSize) {
        this(data, pixelSize, DEFAULT_PIXELATED, DEFAULT_ADDITIONAL_GAP);
    }

    /**
     * Creates a visualizer instance based on pixelSize and, pixelated and
     * additionalGap. Otherwise default values applied.
     * <p>
     * Default values are:
     * <ul>
     * <li>{@link Visualizer#DEFAULT_HEIGHT}</li>
     * <li>{@link Visualizer#DEFAULT_FILE_WIDTH}</li>
     * <li>{@link Visualizer#DEFAULT_LEGEND_WIDTH}</li>
     * </ul>
     * 
     * @param data
     *            the data object of the PE file to visualize
     * @param pixelSize
     *            size of one rectangle that represents a certain amount of
     *            bytes
     * @param pixelated
     *            applies a border to every pixel
     * @param additionalGap
     *            the reduced size on each side of pixels that lie on top of
     *            others, e.g. for the resource section
     */
    public Visualizer(PEData data, int pixelSize, boolean pixelated,
            int additionalGap) {
        this(data, pixelSize, pixelated, additionalGap, DEFAULT_FILE_WIDTH,
                DEFAULT_LEGEND_WIDTH, DEFAULT_HEIGHT);
    }

    /**
     * Creates a visualizer instance.
     * 
     * @param data
     *            the data object of the PE file to visualize
     * @param pixelSize
     *            size of one rectangle that represents a certain amount of
     *            bytes
     * @param pixelated
     *            applies a border to every pixel
     * @param additionalGap
     *            the reduced size on each side of pixels that lie on top of
     *            others, e.g. for the resource section
     * @param fileWidth
     *            the width of the shown file
     * @param legendWidth
     *            the width of the legend
     * @param imageHeight
     *            the height of the image
     */
    public Visualizer(PEData data, int pixelSize, boolean pixelated,
            int additionalGap, int fileWidth, int legendWidth, int imageHeight) {
        this.additionalGap = additionalGap;
        this.fileWidth = fileWidth;
        this.legendWidth = legendWidth;
        this.height = imageHeight;
        this.data = data;
        this.pixelated = pixelated;
        if (pixelated && pixelSize < 2 + additionalGap) {
            this.pixelSize = 2 + additionalGap;
        } else {
            this.pixelSize = pixelSize;
        }
    }

    /**
     * Creates a buffered image that displays the structure of the PE file.
     * 
     * @return buffered image
     * @throws IOException
     *             if sections can not be read
     */
    @Ensures({ "result != null",
            "result.getWidth() == legendWidth + fileWidth",
            "result.getHeight() == height" })
    public BufferedImage createImage() throws IOException {
        image = new BufferedImage(legendWidth + fileWidth, height, IMAGE_TYPE);

        long msdosOffset = 0;
        long msdosSize = withMinLength(data.getMSDOSHeader().getHeaderSize());
        drawPixels(msdosColor, msdosOffset, msdosSize);

        long optOffset = data.getOptionalHeader().getOffset();
        // TODO inaccurate
        long optSize = withMinLength(data.getOptionalHeader().getSize());
        drawPixels(optColor, optOffset, optSize);

        long coffOffset = data.getCOFFFileHeader().getOffset();
        long coffSize = withMinLength(COFFFileHeader.HEADER_SIZE);
        drawPixels(coffColor, coffOffset, coffSize);

        // TODO getSize for every module
        drawSections();

        Overlay overlay = new Overlay(data);
        if (overlay.exists()) {
            long overlayOffset = overlay.getOffset();
            drawPixels(overlayColor, overlayOffset,
                    withMinLength(overlay.getSize()));
            overlayAvailable = true;
        }

        drawSpecials();
        drawLegend();
        return image;
    }

    @Ensures("result > 0")
    private long withMinLength(long length) {
        double minLength = data.getFile().length()
                / (double) (getXPixels() * getYPixels());
        if (minLength < 1) {
            minLength = 1;
        }
        if (length < minLength) {
            return Math.round(minLength);
        }
        return length;
    }

    private void drawSpecials() throws IOException {
        SectionLoader loader = new SectionLoader(data);
        Optional<ImportSection> idata = loader.maybeLoadImportSection();
        if (idata.isPresent()) {
            importsAvailable = true;
            for (Location loc : idata.get().getLocations()) {
                long start = loc.from;
                long size = loc.size;
                System.out.println("start: " + start + " size: " + size);
                drawPixels(importColor, start, size, additionalGap);
            }
        }
        Optional<ExportSection> edata = loader.maybeLoadExportSection();
        if (edata.isPresent()) {
            exportsAvailable = true;
            long offset = edata.get().getOffset();
            long size = edata.get().getSize();
            drawPixels(exportColor, offset, size, additionalGap);
        }

        Optional<ResourceSection> rsrc = loader.maybeLoadResourceSection();
        if (rsrc.isPresent()) {
            resourcesAvailable = true;
            long offset = rsrc.get().getOffset();
            long size = rsrc.get().getSize();
            drawPixels(rsrcColor, offset, size, additionalGap);
        }

        Optional<DebugSection> debug = loader.maybeLoadDebugSection();
        if (debug.isPresent()) {
            debugAvailable = true;
            long offset = debug.get().getOffset();
            long size = debug.get().getSize();
            drawPixels(debugColor, offset, size, additionalGap);
        }
        Optional<Long> ep = getEntryPoint();
        if (ep.isPresent()) {
            epAvailable = true;
            // draw exactly one pixel
            long size = withMinLength(0);
            drawPixels(epColor, ep.get(), size, additionalGap);
        }
    }

    @Ensures("result != null")
    private Optional<Long> getEntryPoint() {
        long rva = data.getOptionalHeader().get(
                StandardFieldEntryKey.ADDR_OF_ENTRY_POINT);
        Optional<SectionHeader> section = new SectionLoader(data)
                .maybeGetSectionHeaderByRVA(rva);
        if (section.isPresent()) {
            long phystovirt = section.get().get(
                    SectionHeaderKey.VIRTUAL_ADDRESS)
                    - section.get().get(SectionHeaderKey.POINTER_TO_RAW_DATA);
            return Optional.of(rva - phystovirt);
        }
        return Optional.absent();
    }

    private void drawSections() {
        SectionTable table = data.getSectionTable();
        long sectionTableOffset = table.getOffset();
        long sectionTableSize = table.getSize();
        drawPixels(sectionTableColor, sectionTableOffset, sectionTableSize);
        Color sectionColor = new Color(sectionColorStart.getRGB());
        for (SectionHeader header : table.getSectionHeaders()) {
            long sectionOffset = header.getAlignedPointerToRaw();
            // TODO put readSize to sectiontable or sectionheader
            long sectionSize = new SectionLoader(data).getReadSize(header);
            drawPixels(sectionColor, sectionOffset, sectionSize);
            sectionColor = variate(sectionColor);
        }
    }

    @Requires("color != null")
    @Ensures("result != null")
    private Color variate(Color color) {
        final int diff = 30;
        Color newColor = new Color(color.getRed() - diff, color.getGreen()
                - diff, color.getBlue() - diff);
        if (newColor.equals(Color.black)) {
            newColor = sectionColorStart;
        }
        return newColor;
    }

    private void drawLegend() {
        drawLegendEntry(1, "MSDOS Header", msdosColor);
        drawLegendEntry(2, "COFF File Header", coffColor);
        drawLegendEntry(3, "Optional Header", optColor);
        drawLegendEntry(4, "Section Table", sectionTableColor);
        int number = 5;
        SectionTable table = data.getSectionTable();
        Color sectionColor = new Color(sectionColorStart.getRGB());
        for (SectionHeader header : table.getSectionHeaders()) {
            drawLegendEntry(number, header.getName(), sectionColor);
            sectionColor = variate(sectionColor);
            number++;
        }
        if (importsAvailable) {
            drawLegendEntry(number, "Imports", importColor, true);
            number++;
        }
        if (exportsAvailable) {
            drawLegendEntry(number, "Exports", exportColor, true);
            number++;
        }
        if (resourcesAvailable) {
            drawLegendEntry(number, "Resources", rsrcColor, true);
            number++;
        }
        if (debugAvailable) {
            drawLegendEntry(number, "Debug", debugColor, true);
            number++;
        }
        if (epAvailable) {
            drawLegendEntry(number, "Entry Point", epColor, true);
            number++;
        }
        if (overlayAvailable) {
            drawLegendEntry(number, "Overlay", overlayColor);
            number++;
        }
    }

    @Requires({ "description != null", "color != null" })
    private void drawLegendEntry(int number, String description, Color color) {
        drawLegendEntry(number, description, color, false);
    }

    @Requires({ "description != null", "color != null" })
    private void drawLegendEntry(int number, String description, Color color,
            boolean withOutLine) {
        int startX = fileWidth + LEGEND_GAP;
        int startY = LEGEND_GAP + (LEGEND_ENTRY_HEIGHT * number);
        if (startY >= height) {
            startX = startX + legendWidth / 2;
            startY = startY - (height);
        }
        drawRect(color, startX, startY, LEGEND_SAMPLE_SIZE, LEGEND_SAMPLE_SIZE);
        if (withOutLine) {
            Graphics g = image.getGraphics();
            g.setColor(Color.black);
            g.drawRect(startX + 1, startY + 1, LEGEND_SAMPLE_SIZE - 3,
                    LEGEND_SAMPLE_SIZE - 3);
        }
        int stringX = startX + LEGEND_SAMPLE_SIZE + LEGEND_GAP;
        int stringY = startY + LEGEND_SAMPLE_SIZE;
        Graphics g = image.getGraphics();
        g.setColor(Color.white);
        g.drawString(description, stringX, stringY);
    }

    @Requires("color != null")
    private void drawRect(Color color, int startX, int startY, int width,
            int height) {
        for (int x = startX; x < startX + width; x++) {
            for (int y = startY; y < startY + height; y++) {
                try {
                    image.setRGB(x, y, color.getRGB());
                } catch (ArrayIndexOutOfBoundsException e) {
                    System.err.println("tried to set x/y = " + x + "/" + y);
                }
            }
        }
    }

    @Requires("color != null")
    private void drawPixels(Color color, long fileOffset, long fileLength) {
        drawPixels(color, fileOffset, fileLength, 0);
    }

    @Requires("color != null")
    private void drawPixels(Color color, long fileOffset, long fileLength,
            int additionalGap) {
        int pixelStart = getPixelNumber(fileOffset);
        // necessary to avoid gaps due to rounding issues (you can't just do
        // getPixelNumber(fileLength))
        int pixelLength = getPixelNumber(fileOffset + fileLength) - pixelStart;
        int pixelMax = getXPixels() * getYPixels();
        if (pixelStart >= pixelMax) {
            System.err.println("too many pixels");
        }
        for (int i = pixelStart; i < pixelStart + pixelLength; i++) {
            int x = (i % getXPixels()) * pixelSize;
            int y = (i / getXPixels()) * pixelSize;
            int gap = pixelated ? additionalGap + 1 : additionalGap;
            int sizemodifier = pixelated ? 2 : 1;
            drawRect(color, x + gap, y + gap, pixelSize - gap * sizemodifier,
                    pixelSize - gap * sizemodifier);
        }
        // Graphics g = image.getGraphics();
        // g.drawString(new Long(fileOffset).toString(), (pixelStart % xPixels)
        // * pixelSize,(pixelStart / xPixels) * pixelSize );
    }

    @Requires("fileOffset >= 0")
    @Ensures("result >= 0")
    private int getPixelNumber(long fileOffset) {
        long fileSize = data.getFile().length();
        return (int) Math.round(fileOffset * (getXPixels() * getYPixels())
                / (double) fileSize);
    }

    public static void main(String[] args) throws IOException {
        File file = new File(
                "/home/deque/portextestfiles/testfiles/strings.exe");
        PEData data = PELoader.loadPE(file);
        String report = PEAnomalyScanner.newInstance(data).scanReport();
        System.out.println(report);
        Visualizer vi = new Visualizer(data);
        final BufferedImage image = vi.createImage();
        ImageIO.write(image, "png", new File(file.getName() + ".png"));
        show(image);
    }

    private static void show(final BufferedImage image) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                JFrame frame = new JFrame();
                frame.setSize(600, 600);
                frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                frame.getContentPane().add(new JLabel(new ImageIcon(image)));
                frame.pack();
                frame.setVisible(true);
            }
        });
    }

    /**
     * Sets the number of file bytes that are represented by one square pixel.
     * The height of the image is changed accordingly.
     */
    @Requires("bytes > 0")
    public void setBytesPerPixel(int bytes) {
        long nrOfPixels = data.getFile().length() / bytes;
        height = (int) (nrOfPixels / fileWidth) * pixelSize;
    }

    /**
     * @see #setAdditionalGap(int)
     * @return additional gap
     */
    @Ensures("result >= 0")
    public int getAdditionalGap() {
        return additionalGap;
    }

    /**
     * Sets the reduced size on each side of square pixels that lie on top of
     * others.
     * 
     * @param additionalGap
     */
    @Requires("additionalGap >= 0")
    public void setAdditionalGap(int additionalGap) {
        this.additionalGap = additionalGap;
    }

    /**
     * @see #setPixelSize(int)
     * @return pixel size
     */
    @Ensures("result > 0")
    public int getPixelSize() {
        return pixelSize;
    }

    /**
     * Sets the length and width of one square pixel.
     * 
     * @param pixelSize
     */
    @Requires("pixelSize > 0")
    public void setPixelSize(int pixelSize) {
        this.pixelSize = pixelSize;
    }

    /**
     * @see #setPixelated(boolean)
     * @return pixelated
     */
    public boolean isPixelated() {
        return pixelated;
    }

    /**
     * Sets pixelated mode, meaning every square pixel in the image has borders
     * if true.
     * 
     * @param pixelated
     */
    public void setPixelated(boolean pixelated) {
        this.pixelated = pixelated;
    }

    /**
     * @see #setFileWidth(int)
     * @return file width
     */
    @Ensures("result > 0")
    public int getFileWidth() {
        return fileWidth;
    }

    /**
     * Sets the width of the PE file representation in (real) pixels.
     * 
     * @param fileWidth
     */
    @Requires("fileWidth > 0")
    public void setFileWidth(int fileWidth) {
        this.fileWidth = fileWidth;
    }

    /**
     * @see #setHeight(int)
     * @return height of the image
     */
    @Ensures("result > 0")
    public int getHeight() {
        return height;
    }

    /**
     * Sets the height of the resulting image, thus also the height of the PE
     * file representation.
     * 
     * @param height
     */
    @Requires("height > 0")
    public void setHeight(int height) {
        this.height = height;
    }

    /**
     * @see #setLegendWidth(int)
     * @return legend width
     */
    @Ensures("result >= 0")
    public int getLegendWidth() {
        return legendWidth;
    }

    /**
     * Sets the width of the legend.
     * <p>
     * Affects only the available space, not font size or similar.
     * 
     * @param legendWidth
     */
    @Requires("legendWidth >= 0")
    public void setLegendWidth(int legendWidth) {
        this.legendWidth = legendWidth;
    }

    @Ensures("result >= 0")
    private int getXPixels() {
        return this.fileWidth / this.pixelSize;
    }

    @Ensures("result >= 0")
    private int getYPixels() {
        return this.height / this.pixelSize;
    }

}
