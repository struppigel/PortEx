package com.github.katjahahn.tools;

import java.awt.Color;
import java.awt.Graphics;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;

import com.github.katjahahn.PEData;
import com.github.katjahahn.PELoader;
import com.github.katjahahn.coffheader.COFFFileHeader;
import com.github.katjahahn.optheader.StandardFieldEntryKey;
import com.github.katjahahn.sections.SectionHeader;
import com.github.katjahahn.sections.SectionHeaderKey;
import com.github.katjahahn.sections.SectionLoader;
import com.github.katjahahn.sections.SectionTable;
import com.github.katjahahn.sections.debug.DebugSection;
import com.github.katjahahn.sections.edata.ExportSection;
import com.github.katjahahn.sections.idata.ImportSection;
import com.github.katjahahn.sections.rsrc.ResourceSection;
import com.github.katjahahn.tools.anomalies.PEAnomalyScanner;

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
     * The default length of the legend is {@value}
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

    private final int additionalGap;
    private final int pixelSize;
    private final boolean pixelated;
    private final int fileWidth;
    private final int height;
    private final int imageWidth;
    private final int legendWidth;
    private final int xPixels;
    private final int yPixels;
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
                DEFAULT_FILE_WIDTH + DEFAULT_LEGEND_WIDTH, DEFAULT_HEIGHT);
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
     * @param imageWidth
     *            the width of the whole image, fileWidth - imageWidth is the
     *            width for the legend
     * @param imageHeight
     *            the height of the image
     */
    public Visualizer(PEData data, int pixelSize, boolean pixelated,
            int additionalGap, int fileWidth, int imageWidth, int imageHeight) {
        this.additionalGap = additionalGap;
        this.fileWidth = fileWidth;
        this.imageWidth = imageWidth;
        this.height = imageHeight;
        this.legendWidth = imageWidth - fileWidth;
        this.data = data;
        this.pixelated = pixelated;
        if (pixelated && pixelSize < 2 + additionalGap) {
            this.pixelSize = 2 + additionalGap;
        } else {
            this.pixelSize = pixelSize;
        }
        this.xPixels = this.fileWidth / this.pixelSize;
        this.yPixels = this.height / this.pixelSize;
    }

    /**
     * Creates a buffered image that displays the structure of the PE file.
     * 
     * @return buffered image
     * @throws IOException
     *             if sections can not be read
     */
    public BufferedImage createImage() throws IOException {
        image = new BufferedImage(imageWidth, height, IMAGE_TYPE);

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

    private long withMinLength(long length) {
        double minLength = data.getFile().length()
                / (double) (xPixels * yPixels);
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
        ImportSection idata = loader.loadImportSection();
        if (idata != null) {
            importsAvailable = true;
            long ilt = idata.getOffset();
            long size = idata.getSize();
            drawPixels(importColor, ilt, size, additionalGap);
        }
        ExportSection edata = loader.loadExportSection();
        if (edata != null) {
            exportsAvailable = true;
            long offset = edata.getOffset();
            long size = edata.getSize();
            drawPixels(exportColor, offset, size, additionalGap);
        }

        ResourceSection rsrc = loader.loadResourceSection();
        if (rsrc != null) {
            resourcesAvailable = true;
            long offset = rsrc.getOffset();
            long size = rsrc.getSize();
            drawPixels(rsrcColor, offset, size, additionalGap);
        }

        DebugSection debug = loader.loadDebugSection();
        if (debug != null) {
            debugAvailable = true;
            long offset = debug.getOffset();
            long size = debug.getSize();
            drawPixels(debugColor, offset, size, additionalGap);
        }
        Long ep = getEntryPoint();
        if (ep != null) {
            epAvailable = true;
            // draw exactly one pixel
            long size = withMinLength(0);
            drawPixels(epColor, ep, size, additionalGap);
        }
    }

    private Long getEntryPoint() {
        long rva = data.getOptionalHeader().get(
                StandardFieldEntryKey.ADDR_OF_ENTRY_POINT);
        SectionHeader section = new SectionLoader(data)
                .getSectionHeaderByRVA(rva);
        if (section != null) {
            long phystovirt = section.get(SectionHeaderKey.VIRTUAL_ADDRESS)
                    - section.get(SectionHeaderKey.POINTER_TO_RAW_DATA);
            return rva - phystovirt;
        }
        return null;
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

    private void drawLegendEntry(int number, String description, Color color) {
        drawLegendEntry(number, description, color, false);
    }

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

    private void drawPixels(Color color, long fileOffset, long fileLength) {
        drawPixels(color, fileOffset, fileLength, 0);
    }

    private void drawPixels(Color color, long fileOffset, long fileLength,
            int additionalGap) {
        int pixelStart = getPixelNumber(fileOffset);
        //necessary to avoid gaps due to rounding issues (you can't just do getPixelNumber(fileLength))
        int pixelLength = getPixelNumber(fileOffset + fileLength) - pixelStart;
        int pixelMax = xPixels * yPixels;
        if (pixelStart >= pixelMax) {
            System.err.println("too many pixels");
        }
        for (int i = pixelStart; i < pixelStart + pixelLength; i++) {
            int x = (i % xPixels) * pixelSize;
            int y = (i / xPixels) * pixelSize;
            int gap = pixelated ? additionalGap + 1 : additionalGap;
            int sizemodifier = pixelated ? 2 : 1;
            drawRect(color, x + gap, y + gap, pixelSize - gap * sizemodifier,
                    pixelSize - gap * sizemodifier);
        }
//        Graphics g = image.getGraphics();
//        g.drawString(new Long(fileOffset).toString(), (pixelStart % xPixels) * pixelSize,(pixelStart / xPixels) * pixelSize );
    }

    private int getPixelNumber(long fileOffset) {
        long fileSize = data.getFile().length();
        return (int) Math.round(fileOffset * (xPixels * yPixels)
                / (double) fileSize);
    }

    public static void main(String[] args) throws IOException {
//        File file = new File("src/main/resources/testfiles/ntdll.dll");
//        File file = new File("src/main/resources/testfiles/DLL1.dll");
        File file = new File("Minecraft.exe");
        PEData data = PELoader.loadPE(file);
        String report = PEAnomalyScanner.getInstance(data).scanReport();
        System.out.println(report);
        Visualizer vi = new Visualizer(data, 8, false, 3, 500, 650, 800);
        final BufferedImage image = vi.createImage();
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

}
