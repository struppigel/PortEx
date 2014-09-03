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
package com.github.katjahahn.tools.visualizer;

import static com.github.katjahahn.parser.optheader.DataDirectoryKey.*;
import static com.github.katjahahn.tools.visualizer.ColorableItem.*;

import java.awt.Color;
import java.awt.Graphics;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.parser.Location;
import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoader;
import com.github.katjahahn.parser.PhysicalLocation;
import com.github.katjahahn.parser.coffheader.COFFFileHeader;
import com.github.katjahahn.parser.optheader.DataDirectoryKey;
import com.github.katjahahn.parser.optheader.StandardFieldEntryKey;
import com.github.katjahahn.parser.sections.SectionHeader;
import com.github.katjahahn.parser.sections.SectionHeaderKey;
import com.github.katjahahn.parser.sections.SectionLoader;
import com.github.katjahahn.parser.sections.SectionTable;
import com.github.katjahahn.parser.sections.SpecialSection;
import com.github.katjahahn.tools.Overlay;
import com.github.katjahahn.tools.ReportCreator;
import com.github.katjahahn.tools.ShannonEntropy;
import com.github.katjahahn.tools.anomalies.Anomaly;
import com.github.katjahahn.tools.anomalies.PEAnomalyScanner;
import com.github.katjahahn.tools.visualizer.VisualizerBuilder.VisualizerSettings;
import com.google.common.base.Optional;

/**
 * Creates an image that represents the structure of a PE file on disk.
 * 
 * @author Katja Hahn
 * 
 */
public class Visualizer {
    // TODO handling duplicated sections
    // TODO anomaly visualizing in separate class

    private static final Logger logger = LogManager.getLogger(Visualizer.class
            .getName());

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

    private PEData data;
    private BufferedImage image;

    private static final DataDirectoryKey[] specials = { BASE_RELOCATION_TABLE,
            IMPORT_TABLE, DELAY_IMPORT_DESCRIPTOR, EXPORT_TABLE,
            RESOURCE_TABLE, DEBUG };

    private Map<DataDirectoryKey, Boolean> specialsAvailability = new EnumMap<>(
            DataDirectoryKey.class);
    {
        for (DataDirectoryKey key : specials) {
            specialsAvailability.put(key, false);
        }
    }

    // TODO put into colorable
    private Map<DataDirectoryKey, ColorableItem> specialsColorable = new EnumMap<>(
            DataDirectoryKey.class);
    {
        specialsColorable.put(BASE_RELOCATION_TABLE, RELOC_SECTION);
        specialsColorable.put(IMPORT_TABLE, IMPORT_SECTION);
        specialsColorable.put(DELAY_IMPORT_DESCRIPTOR, DELAY_IMPORT_SECTION);
        specialsColorable.put(EXPORT_TABLE, EXPORT_SECTION);
        specialsColorable.put(RESOURCE_TABLE, RESOURCE_SECTION);
        specialsColorable.put(DEBUG, DEBUG_SECTION);
    }

    private boolean overlayAvailable;
    private boolean epAvailable;

    private Map<ColorableItem, Color> colorMap;

    /**
     * Creates a visualizer instance.
     * 
     * @param settings
     *            the settings for the visualizer
     */
    Visualizer(VisualizerSettings settings) {
        this.additionalGap = settings.additionalGap;
        this.fileWidth = settings.fileWidth;
        this.legendWidth = settings.legendWidth;
        this.height = settings.height;
        this.pixelated = settings.pixelated;
        // TODO maybe check this in builder
        if (settings.pixelated
                && settings.pixelSize < 2 + settings.additionalGap) {
            this.pixelSize = 2 + settings.additionalGap;
        } else {
            this.pixelSize = settings.pixelSize;
        }
        this.colorMap = settings.colorMap;
    }

    // TODO optimize
    /**
     * Creates an image of the local entropies of this file.
     * 
     * @param file
     *            the PE file
     * @return image of local entropies
     * @throws IOException
     *             if file can not be read
     */
    public BufferedImage createEntropyImage(File file) throws IOException {
        this.data = PELoader.loadPE(file);
        image = new BufferedImage(fileWidth, height, IMAGE_TYPE);
        byte[] bytes = Files.readAllBytes(data.getFile().toPath());
        double[] entropies = ShannonEntropy.localEntropies(bytes);
        for (int i = 0; i < entropies.length; i += withMinLength(0)) {
            int col = (int) (entropies[i] * 255);
            Color color = new Color(col, col, col);
            long minLength = withMinLength(0);
            drawPixels(color, i, minLength);
        }
        return image;
    }

    /**
     * Creates a buffered image that displays the structure of the PE file.
     * 
     * @param file
     *            the PE file to create an image from
     * @return buffered image
     * @throws IOException
     *             if sections can not be read
     */
    public BufferedImage createImage(File file) throws IOException {
        this.data = PELoader.loadPE(file);
        image = new BufferedImage(legendWidth + fileWidth, height, IMAGE_TYPE);

        drawSections();

        long msdosOffset = 0;
        long msdosSize = withMinLength(data.getMSDOSHeader().getHeaderSize());
        drawPixels(colorMap.get(MSDOS_HEADER), msdosOffset, msdosSize);

        long optOffset = data.getOptionalHeader().getOffset();
        long optSize = withMinLength(data.getOptionalHeader().getSize());
        drawPixels(colorMap.get(OPTIONAL_HEADER), optOffset, optSize);

        long coffOffset = data.getCOFFFileHeader().getOffset();
        long coffSize = withMinLength(COFFFileHeader.HEADER_SIZE);
        drawPixels(colorMap.get(COFF_FILE_HEADER), coffOffset, coffSize);

        long tableOffset = data.getSectionTable().getOffset();
        long tableSize = data.getSectionTable().getSize();
        if (tableSize != 0) {
            tableSize = withMinLength(tableSize);
            drawPixels(colorMap.get(SECTION_TABLE), tableOffset, tableSize);
        }

        Overlay overlay = new Overlay(data);
        if (overlay.exists()) {
            long overlayOffset = overlay.getOffset();
            drawPixels(colorMap.get(OVERLAY), overlayOffset,
                    withMinLength(overlay.getSize()));
            overlayAvailable = true;
        }

        drawSpecials();
        // drawAnomalies();
        drawLegend();
        assert image != null;
        assert image.getWidth() == legendWidth + fileWidth;
        assert image.getHeight() == height;
        return image;
    }

    // TODO create own visualizer for that task, maybe with decorator pattern
    @SuppressWarnings("unused")
    private void drawAnomalies() {
        PEAnomalyScanner scanner = PEAnomalyScanner.newInstance(data);
        List<Anomaly> anomalies = scanner.getAnomalies();
        for (Anomaly anomaly : anomalies) {
            List<PhysicalLocation> locs = anomaly.locations();
            for (PhysicalLocation loc : locs) {
                drawCrosses(colorMap.get(ANOMALY), loc.from(),
                        withMinLength(loc.size()));
            }
        }
    }

    private long withMinLength(long length) {
        double minLength = data.getFile().length()
                / (double) (getXPixels() * getYPixels());
        if (minLength < 1) {
            minLength = 1;
        }
        if (length < minLength) {
            return Math.round(minLength);
        }
        assert length > 0;
        return length;
    }
    
    private String getSpecialsDescription(DataDirectoryKey key) {
        ColorableItem colorableItem = specialsColorable.get(key);
        return colorableItem.getLegendDescription();
    }

    private Color getSpecialsColor(DataDirectoryKey key) {
        ColorableItem colorableItem = specialsColorable.get(key);
        return colorMap.get(colorableItem);
    }

    private void drawSpecials() throws IOException {
        SectionLoader loader = new SectionLoader(data);

        for (DataDirectoryKey specialKey : specials) {
            Optional<? extends SpecialSection> section = loader
                    .maybeLoadSpecialSection(specialKey);
            if (section.isPresent()) {
                specialsAvailability.put(specialKey, true);
                for (Location loc : section.get().getPhysicalLocations()) {
                    long start = loc.from();
                    if (start == -1) {
                        // FIXME this happens with rsrc section and
                        // VirusShare_1eb8065cebc74e752fd4f085f05d62d9, why?
                        logger.warn(specialKey
                                + " location starts from -1 (will be ignored): "
                                + loc);
                        continue;
                    }
                    long size = withMinLength(loc.size());
                    drawPixels(getSpecialsColor(specialKey), start, size,
                            additionalGap);
                }
            }
        }
        Optional<Long> ep = getEntryPoint();
        if (ep.isPresent()) {
            epAvailable = true;
            // draw exactly one pixel
            long size = withMinLength(0);
            drawPixels(colorMap.get(ENTRY_POINT), ep.get(), size, additionalGap);
        }
    }

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
        drawPixels(colorMap.get(SECTION_TABLE), sectionTableOffset,
                sectionTableSize);
        for (SectionHeader header : table.getSectionHeaders()) {
            long sectionOffset = header.getAlignedPointerToRaw();
            long sectionSize = new SectionLoader(data).getReadSize(header);
            drawPixels(getSectionColor(header), sectionOffset, sectionSize);
        }
    }

    private Color getSectionColor(SectionHeader header) {
        int nr = header.getNumber();
        Color sectionColor = colorMap.get(SECTION_START);
        for (int i = 1; i < nr; i++) {
            sectionColor = variate(sectionColor);
        }
        return sectionColor;
    }

    private Color variate(Color color) {
        assert color != null;
        final int diff = 30;
        int newRed = shiftColorPart(color.getRed() - diff);
        int newGreen = shiftColorPart(color.getGreen() - diff);
        int newBlue = shiftColorPart(color.getBlue() - diff);
        Color newColor = new Color(newRed, newGreen, newBlue);
        if (newColor.equals(Color.black)) {
            newColor = colorMap.get(SECTION_START);
        }
        return newColor;
    }

    private int shiftColorPart(int colorPart) {
        if (colorPart < 0) {
            return 255;
        }
        if (colorPart > 255) {
            return 0;
        }

        return colorPart;
    }

    private void drawLegend() {
        drawLegendEntry(0, "MSDOS Header", colorMap.get(MSDOS_HEADER));
        drawLegendEntry(1, "COFF File Header", colorMap.get(COFF_FILE_HEADER));
        drawLegendEntry(2, "Optional Header", colorMap.get(OPTIONAL_HEADER));
        drawLegendEntry(3, "Section Table", colorMap.get(SECTION_TABLE));
        int number = 4;
        SectionTable table = data.getSectionTable();
        for (SectionHeader header : table.getSectionHeaders()) {
            Color sectionColor = getSectionColor(header);
            drawLegendEntry(number, header.getName(), sectionColor);
            sectionColor = variate(sectionColor);
            number++;
        }
        for (DataDirectoryKey special : specials) {
            if (specialsAvailability.get(special)) {
                drawLegendEntry(number, getSpecialsDescription(special),
                        getSpecialsColor(special), true);
                number++;
            }
        }
        if (epAvailable) {
            drawLegendEntry(number, "Entry Point", colorMap.get(ENTRY_POINT),
                    true);
            number++;
        }
        if (overlayAvailable) {
            drawLegendEntry(number, "Overlay", colorMap.get(OVERLAY));
            number++;
        }
        // drawLegendCrossEntry(number, "Anomalies", anomalyColor);
    }

    // TODO temporary almost-duplicate of drawLegendEntry
    @SuppressWarnings("unused")
    private void drawLegendCrossEntry(int number, String description,
            Color color) {
        assert description != null && color != null;
        int startX = fileWidth + LEGEND_GAP;
        int startY = LEGEND_GAP + (LEGEND_ENTRY_HEIGHT * number);
        if (startY >= height) {
            startX = startX + legendWidth / 2;
            startY = startY - (height);
        }
        drawCross(color, startX, startY, LEGEND_SAMPLE_SIZE, LEGEND_SAMPLE_SIZE);
        int stringX = startX + LEGEND_SAMPLE_SIZE + LEGEND_GAP;
        int stringY = startY + LEGEND_SAMPLE_SIZE;
        Graphics g = image.getGraphics();
        g.setColor(Color.white);
        g.drawString(description, stringX, stringY);
    }

    private void drawLegendEntry(int number, String description, Color color) {
        assert description != null && color != null;
        drawLegendEntry(number, description, color, false);
    }

    private void drawLegendEntry(int number, String description, Color color,
            boolean withOutLine) {
        assert description != null && color != null;
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

    private void drawRect(Color color, int startX, int startY, int width,
            int height) {
        assert color != null;
        for (int x = startX; x < startX + width; x++) {
            for (int y = startY; y < startY + height; y++) {
                try {
                    image.setRGB(x, y, color.getRGB());
                } catch (ArrayIndexOutOfBoundsException e) {
                    logger.error("tried to set x/y = " + x + "/" + y);
                }
            }
        }
    }

    // TODO temporary almost-duplicate of drawRect
    private void drawCross(Color color, int startX, int startY, int width,
            int height) {
        assert color != null;
        final int thickness = 2;
        for (int x = startX; x < startX + width; x++) {
            for (int y = startY; y < startY + height; y++) {
                try {
                    if (Math.abs((x - startX) - (y - startY)) < thickness
                            || Math.abs((width - (x - startX)) - (y - startY)) < thickness) {
                        image.setRGB(x, y, color.getRGB());
                    }
                } catch (ArrayIndexOutOfBoundsException e) {
                    logger.error("tried to set x/y = " + x + "/" + y);
                }
            }
        }
    }

    // TODO temporary almost-duplicate of drawPixels
    private void drawCrosses(Color color, long fileOffset, long fileLength) {
        assert color != null;
        int pixelStart = getPixelNumber(fileOffset);
        // necessary to avoid gaps due to rounding issues (you can't just do
        // getPixelNumber(fileLength))
        int pixelLength = getPixelNumber(fileOffset + fileLength) - pixelStart;
        int pixelMax = getXPixels() * getYPixels();
        if (pixelStart >= pixelMax) {
            logger.error("too many pixels, max is: " + pixelMax
                    + " and trying to set: " + pixelStart);
        }
        for (int i = pixelStart; i < pixelStart + pixelLength; i++) {
            int x = (i % getXPixels()) * pixelSize;
            int y = (i / getXPixels()) * pixelSize;
            int sizemodifier = pixelated ? 2 : 1;
            drawCross(color, x, y, pixelSize * sizemodifier, pixelSize
                    * sizemodifier);
        }
    }

    private void drawPixels(Color color, long fileOffset, long fileLength) {
        assert color != null;
        drawPixels(color, fileOffset, fileLength, 0);
    }

    private void drawPixels(Color color, long fileOffset, long fileLength,
            int additionalGap) {
        assert color != null;
        int pixelStart = getPixelNumber(fileOffset);
        // necessary to avoid gaps due to rounding issues (you can't just do
        // getPixelNumber(fileLength))
        int pixelLength = getPixelNumber(fileOffset + fileLength) - pixelStart;
        int pixelMax = getXPixels() * getYPixels();
        if (pixelStart >= pixelMax) {
            logger.error("too many pixels, max is: " + pixelMax
                    + " and trying to set: " + pixelStart);
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

    private int getPixelNumber(long fileOffset) {
        assert fileOffset >= 0;
        long fileSize = data.getFile().length();
        int result = (int) Math.round(fileOffset
                * (getXPixels() * getYPixels()) / (double) fileSize);
        assert result >= 0;
        return result;
    }

    /**
     * For testing purposes only.
     * 
     * @param args
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {
        // TODO check tinyPE out of bounds pixel setting
        File file = new File(
                "/home/deque/portextestfiles/unusualfiles/corkami/delay_imports.exe");
        PEData data = PELoader.loadPE(file);
        new ReportCreator(data).printReport();
        Visualizer vi = new VisualizerBuilder().build();
        final BufferedImage entropyImage = vi.createEntropyImage(file);
        final BufferedImage structureImage = vi.createImage(file);
        final BufferedImage appendedImage = ImageUtil.appendImages(
                entropyImage, structureImage);
        // ImageIO.write(image, "png", new File(file.getName() + ".png"));
        show(appendedImage);
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
     * @return additional gap
     */
    public int getAdditionalGap() {
        assert additionalGap >= 0;
        return additionalGap;
    }

    /**
     * @return pixel size
     */
    public int getPixelSize() {
        assert pixelSize > 0;
        return pixelSize;
    }

    /**
     * @return pixelated
     */
    public boolean isPixelated() {
        return pixelated;
    }

    /**
     * @return file width
     */
    public int getFileWidth() {
        assert fileWidth > 0;
        return fileWidth;
    }

    /**
     * @return height of the image
     */
    public int getHeight() {
        assert height > 0;
        return height;
    }

    /**
     * @return legend width
     */
    public int getLegendWidth() {
        assert legendWidth >= 0;
        return legendWidth;
    }

    private int getXPixels() {
        int result = (int) Math.ceil(this.fileWidth / (double) this.pixelSize);
        assert result >= 0;
        return result;
    }

    private int getYPixels() {
        int result = (int) Math.ceil(this.height / (double) this.pixelSize);
        assert result >= 0;
        return result;
    }

}
