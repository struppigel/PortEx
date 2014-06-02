package com.github.katjahahn.tools;

import java.awt.Color;
import java.awt.Graphics;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JLabel;

import com.github.katjahahn.PEData;
import com.github.katjahahn.PELoader;
import com.github.katjahahn.coffheader.COFFFileHeader;
import com.github.katjahahn.sections.SectionHeader;
import com.github.katjahahn.sections.SectionLoader;
import com.github.katjahahn.sections.SectionTable;

public class Visualizer {

	private static final int DEFAULT_WIDTH = 300;
	private static final int DEFAULT_HEIGHT = 600;
	private static final int IMAGE_TYPE = BufferedImage.TYPE_INT_RGB;
	private static final int LEGEND_WIDTH = 200;
	private static final int LEGEND_SAMPLE_SIZE = 10;
	private static final int LEGEND_GAP = 10;
	private static final int LEGEND_ENTRY_HEIGHT = 20;
	private static final int PIXEL_SIZE = 2;
	
	private final int fileWidth = DEFAULT_WIDTH;
	private final int height = DEFAULT_HEIGHT;
	private final int imageWidth = DEFAULT_WIDTH + LEGEND_WIDTH;
	private final int xPixels = fileWidth / PIXEL_SIZE;
	private final int yPixels = height / PIXEL_SIZE;
	private final Color msdosColor = new Color(0, 0, 200);
	private final Color coffColor = new Color(0, 200, 0);
	private final Color optColor = new Color(200, 0, 0);
	private final Color sectionTableColor = new Color(200, 200, 0);
	private final Color sectionColorStart = new Color(220, 220, 220);
	private final Color overlayColor = new Color(100, 100, 240);

	private final PEData data;
	private BufferedImage image;

	public Visualizer(PEData data) {
		this.data = data;
	}

	public BufferedImage createImage() throws IOException {
		image = new BufferedImage(imageWidth, height, IMAGE_TYPE);

		long msdosOffset = 0;
		final int msdosSize = (int) data.getPESignature().getOffset();
		drawPixels(msdosColor, msdosOffset, msdosSize);

		long coffOffset = data.getCOFFFileHeader().getOffset();
		long coffSize = COFFFileHeader.HEADER_SIZE;
		drawPixels(coffColor, coffOffset, coffSize);

		long optOffset = data.getOptionalHeader().getOffset();
		// TODO inaccurate
		long optSize = data.getCOFFFileHeader().getSizeOfOptionalHeader();
		drawPixels(optColor, optOffset, optSize);

		// TODO getSize for every module
		drawSections();

		Overlay overlay = new Overlay(data);
		long overlayOffset = overlay.getOffset();
		drawPixels(overlayColor, overlayOffset, overlay.getSize());

		drawLegend();
		return image;
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
			System.out.println("section at offset: " + sectionOffset);
			drawPixels(sectionColor, sectionOffset, sectionSize);
			sectionColor = variate(sectionColor);
		}
	}
	
	private Color variate(Color color) {
		int diff = 10;
		Color newColor = new Color(color.getRed() - diff, color.getGreen() - diff, color.getBlue() - diff);
		if(newColor.equals(Color.black)) {
			newColor = sectionColorStart;
		}
		return newColor;
	}

	private void drawLegend() {
		drawLegendEntry(1, "MSDOS Stub", msdosColor);
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
		drawLegendEntry(number, "Overlay", overlayColor);
	}
	
	private void drawLegendEntry(int number, String description, Color color) {
		int startX = fileWidth + LEGEND_GAP;
		int startY = LEGEND_GAP + (LEGEND_ENTRY_HEIGHT * number);
		if(startY >= height) {
			startX = startX + LEGEND_WIDTH/2;
			startY = startY - (height);
		}
		drawRect(color, startX, startY, LEGEND_SAMPLE_SIZE,
				LEGEND_SAMPLE_SIZE);
		int stringX = startX + LEGEND_SAMPLE_SIZE + LEGEND_GAP;
		int stringY = startY + LEGEND_SAMPLE_SIZE;
		Graphics g = image.getGraphics();
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
		int pixelStart = getPixelNumber(fileOffset);
		int pixelNumber = getPixelNumber(fileLength);
		for (int i = pixelStart; i < pixelStart + pixelNumber; i++) {
			int x = (i % xPixels) * PIXEL_SIZE;
			int y = (i / xPixels) * PIXEL_SIZE;
			drawRect(color, x, y, PIXEL_SIZE, PIXEL_SIZE);
		}

	}

	private int getPixelNumber(long fileOffset) {
		long fileSize = data.getFile().length();
		return (int) Math.ceil(fileOffset * (xPixels * yPixels)
				/ (double) fileSize);
	}

	public static void main(String[] args) throws IOException {
		File file = new File("src/main/resources/unusualfiles/corkami/max_secXP.exe");
		PEData data = PELoader.loadPE(file);
		System.out.println("sections: " + data.getCOFFFileHeader().getNumberOfSections());
		Visualizer vi = new Visualizer(data);
		BufferedImage image = vi.createImage();
		JFrame frame = new JFrame();
		frame.setSize(600, 600);
		frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		frame.getContentPane().add(new JLabel(new ImageIcon(image)));
		frame.pack();
		frame.setVisible(true);
	}

}
