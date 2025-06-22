/*******************************************************************************
 * Copyright 2014 Karsten Philipp Boris Hahn
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
package io.github.struppigel.tools.visualizer;


import io.github.struppigel.parser.coffheader.COFFFileHeader;
import io.github.struppigel.parser.optheader.DataDirectoryKey;
import io.github.struppigel.parser.optheader.StandardFieldEntryKey;
import io.github.struppigel.parser.sections.*;
import io.github.struppigel.parser.Location;
import io.github.struppigel.parser.PhysicalLocation;
import io.github.struppigel.parser.sections.clr.CLRSection;
import io.github.struppigel.parser.sections.clr.StreamHeader;
import io.github.struppigel.parser.sections.rsrc.Resource;
import io.github.struppigel.parser.sections.rsrc.ResourceSection;
import io.github.struppigel.tools.Overlay;
import io.github.struppigel.tools.ShannonEntropy;
import io.github.struppigel.tools.anomalies.Anomaly;
import io.github.struppigel.tools.anomalies.PEAnomalyScanner;
import io.github.struppigel.tools.visualizer.VisualizerBuilder.VisualizerSettings;
import io.github.struppigel.parser.*;
import com.google.common.base.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.github.struppigel.parser.optheader.DataDirectoryKey.*;
import static io.github.struppigel.tools.visualizer.ColorableItem.*;

/**
 * Creates an image that represents the structure of a PE file on disk.
 * 
 * @author Karsten Philipp Boris Hahn
 * 
 */
public class Visualizer {

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
	private long fileSize;

	private PEData data;
	private BufferedImage image;

	private static final DataDirectoryKey[] specials = { RESOURCE_TABLE,
			IMPORT_TABLE, DELAY_IMPORT_DESCRIPTOR, EXPORT_TABLE,
			BASE_RELOCATION_TABLE, DEBUG };
	private Map<String, Color> resTypeColors = new HashMap<>();

	private Map<DataDirectoryKey, Boolean> specialsAvailability = new EnumMap<>(
			DataDirectoryKey.class);
	{
		for (DataDirectoryKey key : specials) {
			specialsAvailability.put(key, false);
		}
	}

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

	private List<PhysicalLocation> visOverlay;

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
		this.visOverlay = settings.visOverlay;
		// TODO maybe check this in builder
		if (settings.pixelated
				&& settings.pixelSize < 2 + settings.additionalGap) {
			this.pixelSize = 2 + settings.additionalGap;
		} else {
			this.pixelSize = settings.pixelSize;
		}
		logger.info("vis settings: fileWidth = " + fileWidth);
		logger.info("vis settings: height = " + height);
		logger.info("vis settings: pixelSize = " + pixelSize);
		this.colorMap = settings.colorMap;
	}

	public BufferedImage createBytePlot(File file) throws IOException {
		resetAvailabilityFlags();
		if(!isPEFile(file)) {
			this.data = new PEData(null, null, null, null, null, file, null);
		} else {
			this.data = PELoader.loadPE(file);
		}
		this.fileSize = data.getFile().length();
		image = new BufferedImage(fileWidth, height, IMAGE_TYPE);
		final long minLength = withMinLength(0);
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			for (long address = 0; address < fileSize; address += minLength) {
				raf.seek(address);
				byte b = raf.readByte();
				Color color = getBytePlotColor(b);
				drawPixel(color, address);
			}
		}
		drawVisOverlay(false);
		return image;
	}

	private boolean isPEFile(File file) {
		try {
			PELoader.loadPE(file);
			return true;
		} catch (FileFormatException e) {
			return false;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private Color getBytePlotColor(byte b) {
		/* convert byte to int */
		int byteVal = b & 0xff;
		/* unpack colors */
		Color visibleASCII = colorMap.get(VISIBLE_ASCII);
		Color invisibleASCII = colorMap.get(INVISIBLE_ASCII);
		Color nonASCII = colorMap.get(NON_ASCII);
		/* get hue for each color */
		float[] hsbvals = new float[3];
		Color.RGBtoHSB(visibleASCII.getRed(), visibleASCII.getGreen(),
				visibleASCII.getBlue(), hsbvals);
		float visibleASCIIHue = hsbvals[0];
		float visibleASCIISaturation = hsbvals[1];
		Color.RGBtoHSB(invisibleASCII.getRed(), invisibleASCII.getGreen(),
				invisibleASCII.getBlue(), hsbvals);
		float invisibleASCIIHue = hsbvals[0];
		float invisibleASCIISaturation = hsbvals[1];
		Color.RGBtoHSB(nonASCII.getRed(), nonASCII.getGreen(),
				nonASCII.getBlue(), hsbvals);
		float nonASCIIHue = hsbvals[0];
		float nonASCIISaturation = hsbvals[1];

		/* max or min byte value */
		if (byteVal == 0)
			return colorMap.get(MIN_BYTE);
		if (byteVal == 0xff)
			return colorMap.get(MAX_BYTE);

		/* ASCII range */
		if (byteVal > 0 && byteVal <= 127) {
			float hue = visibleASCIIHue;
			float saturation = visibleASCIISaturation;
			if (byteVal < 33 || byteVal == 127) {
				hue = invisibleASCIIHue;
				saturation = invisibleASCIISaturation;
			}
			float brightness = (float) (byteVal / (float) 127);
			return Color.getHSBColor(hue, saturation, brightness);
		} else { /* non-ASCII range */
			float brightness = (float) ((byteVal - 127) / (float) (255 - 127));
			return Color.getHSBColor(nonASCIIHue, nonASCIISaturation,
					brightness);
		}
	}

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
		resetAvailabilityFlags();
		if(!isPEFile(file)) {
			this.data = new PEData(null, null, null, null, null, file, null);
		} else {
			this.data = PELoader.loadPE(file);
		}
		this.fileSize = data.getFile().length();
		image = new BufferedImage(fileWidth, height, IMAGE_TYPE);
		final int MIN_WINDOW_SIZE = 100;
		// bytes to be read at once to calculate local entropy
		final int windowSize = Math.max(MIN_WINDOW_SIZE, pixelSize);
		final int windowHalfSize = (int) Math.round(windowSize / (double) 2);
		final long minLength = withMinLength(0);
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			// read until EOF with windowSized steps
			for (long address = 0; address <= fileSize; address += minLength) {
				// the start of the window (windowHalf to the left)
				long start = (address - windowHalfSize < 0) ? 0 : address
						- windowHalfSize;
				raf.seek(start);
				// cut byte number if EOF reached, otherwise read full window
				int bytesToRead = (int) Math.min(fileSize - start,
						windowSize);
				byte[] bytes = new byte[bytesToRead];
				raf.readFully(bytes);
				/* calculate and draw entropy square pixel for this window */
				double entropy = ShannonEntropy.entropy(bytes);
				Color color = getColorForEntropy(entropy);
				drawPixels(color, address, minLength);
			}
		}
		drawVisOverlay(true);
		return image;
	}

	/**
	 * Creates a color instance based on a given entropy.
	 * 
	 * @param entropy
	 *            value between 0 and 1
	 * @return Color for given entropy
	 */
	private Color getColorForEntropy(double entropy) {
		assert entropy <= 1;
		assert entropy >= 0;
		Color entropyColor = colorMap.get(ENTROPY);
		float[] hsbvals = new float[3];
		Color.RGBtoHSB(entropyColor.getRed(), entropyColor.getGreen(),
				entropyColor.getBlue(), hsbvals);
		float entropyHue = hsbvals[0];
		float saturation = hsbvals[1];
		float brightness = (float) entropy;
		return Color.getHSBColor(entropyHue, saturation, brightness);
		// int col = (int) (entropy * 255);
		// return new Color(col, col, col);
	}

	/**
	 * Sets all *Available flags to false.
	 */
	private void resetAvailabilityFlags() {
		epAvailable = false;
		overlayAvailable = false;
		for (DataDirectoryKey key : specials) {
			specialsAvailability.put(key, false);
		}
	}

	/**
	 * Writes an image to the output file that displays the structure of the PE
	 * file.
	 * <p>
	 * The output image format is PNG.
	 * 
	 * @param input
	 *            the PE file to create an image from
	 * @param output
	 *            the file to write the image to
	 * @throws IOException
	 *             if sections can not be read
	 */
	public void writeImage(File input, File output) throws IOException {
		writeImage(input, output, "png");
	}

	/**
	 * Writes an image to the output file that displays the structure of the PE
	 * file.
	 * 
	 * @param input
	 *            the PE file to create an image from
	 * @param output
	 *            the file to write the image to
	 * @param formatName
	 *            the format name for the output image
	 * @throws IOException
	 *             if sections can not be read
	 */
	public void writeImage(File input, File output, String formatName)
			throws IOException {
		BufferedImage image = createImage(input);
		ImageIO.write(image, formatName, output);
	}

	/**
	 * Creates a buffered image containing the diff of both files.
	 * 
	 * @param firstImage
	 * @param secondImage
	 * @return
	 * @throws IOException
	 */
	public BufferedImage createDiffImage(BufferedImage firstImage,
			BufferedImage secondImage) throws IOException {
		BufferedImage diffImage = new BufferedImage(firstImage.getWidth(),
				firstImage.getHeight(), IMAGE_TYPE);

		for (int x = 0; x < firstImage.getWidth() && x < secondImage.getWidth(); x++) {
			for (int y = 0; y < firstImage.getHeight()
					&& y < secondImage.getHeight(); y++) {
				int pixelA = firstImage.getRGB(x, y);
				int pixelB = secondImage.getRGB(x, y);
				int diffRGB = Math.abs(pixelA - pixelB);
				diffImage.setRGB(x, y, diffRGB);
			}
		}
		return diffImage;
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
		resetAvailabilityFlags();
		this.data = PELoader.loadPE(file);
		this.fileSize = data.getFile().length();
		image = new BufferedImage(fileWidth, height, IMAGE_TYPE);

		drawSections();

		Overlay overlay = new Overlay(data);
		if (overlay.exists()) {
			long overlayOffset = overlay.getOffset();
			drawPixels(colorMap.get(OVERLAY), overlayOffset,
					withMinLength(overlay.getSize()));
			overlayAvailable = true;
		}

		drawPEHeaders();
		drawSpecials();
		drawResourceTypes();
		assert image != null;
		assert image.getWidth() == fileWidth;
		assert image.getHeight() == height;
		return image;
	}

	/**
	 * Creates a buffered image with a basic Legend
	 * 
	 * @param withBytePlot
	 *            show byteplot legend
	 * @param withEntropy
	 *            show entropy legend
	 * @param withPEStructure
	 *            show PE structure legend
	 * @return buffered image of the generated legend
	 */
	public BufferedImage createLegendImage(boolean withBytePlot,
			boolean withEntropy, boolean withPEStructure) throws IOException {
		image = new BufferedImage(legendWidth, height, IMAGE_TYPE);
		drawLegend(withBytePlot, withEntropy, withPEStructure);
		assert image != null;
		assert image.getWidth() == legendWidth;
		assert image.getHeight() == height;
		return image;
	}

	private void drawResourceTypes() {
		SectionLoader loader = new SectionLoader(data);
		ResourceSection rsrc;
		try {
			Optional<ResourceSection> maybeRsrc = loader
					.maybeLoadResourceSection();
			if (maybeRsrc.isPresent()) {
				rsrc = maybeRsrc.get();
				List<Resource> resources = rsrc.getResources();
				Color color = new Color(220, 255, 220);
				for (Resource r : resources) {
					String resType = r.getType();
					PhysicalLocation loc = r.rawBytesLocation();
					long start = loc.from();
					long size = withMinLength(loc.size());
					if (resTypeColors.containsKey(resType)) {
						drawPixels(resTypeColors.get(resType), start, size,
								additionalGap);
					} else {
						drawPixels(color, start, size, additionalGap);
						resTypeColors.put(resType, color);
						color = variate(color);
					}
				}
			}
		} catch (IOException e) {
			logger.error(e.getMessage());
			e.printStackTrace();
		}
	}

	/**
	 * Draws the PE Header to the structure image
	 */
	private void drawPEHeaders() throws IOException {
		long msdosOffset = 0;
		long msdosSize = withMinLength(data.getMSDOSHeader().getHeaderSize());
		drawPixels(colorMap.get(MSDOS_HEADER), msdosOffset, msdosSize);

		if(data.maybeGetRichHeader().isPresent()){
			long richOffset = data.maybeGetRichHeader().get().getPhysicalLocation().from();
			long richSize = withMinLength(data.maybeGetRichHeader().get().getPhysicalLocation().size());
			drawPixels(colorMap.get(RICH_HEADER), richOffset, richSize);
		}


		Optional<CLRSection> maybeClr = new SectionLoader(data).maybeLoadCLRSection();
		if(maybeClr.isPresent()){
			// CLR Meta
			CLRSection clr = maybeClr.get();
			long bsjb = clr.metadataRoot().getBSJBOffset();
			Color clrColor = colorMap.get(CLR_SECTION);
			for(PhysicalLocation loc : clr.getPhysicalLocations()){
				drawPixels(clrColor,loc.from(), withMinLength(loc.size()));
			}
			// Streams
			List<StreamHeader> headers = clr.metadataRoot().getStreamHeaders();
			Color color = colorMap.get(NET_STREAMS);
			for (StreamHeader header : headers) {
				long heapOffset = header.offset() + bsjb;
				long heapSize = withMinLength(header.size());
				drawPixels(color, heapOffset, heapSize);
				color = variate(color);
			}
		}

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
		double minLength = fileSize
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
		drawVisOverlay(true);
	}

	private void drawVisOverlay(boolean withGap) {
		if (visOverlay != null) {
			for (Location loc : visOverlay) {
				long start = loc.from();
				long size = withMinLength(loc.size());
				if (withGap) {
					drawPixels(colorMap.get(VISOVERLAY), start, size,
							additionalGap);
				} else {
					drawPixels(colorMap.get(VISOVERLAY), start, size);
				}
			}
		}
	}

	/**
	 * Returns the entry point of the PE if present and valid, otherwise absent.
	 * 
	 * A valid entry point is one within a section.
	 * 
	 * @return entry point optional if present, absent otherwise
	 */
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

	/**
	 * Draw the sections to the structure image.
	 */
	private void drawSections() {
		SectionTable table = data.getSectionTable();
		long sectionTableOffset = table.getOffset();
		long sectionTableSize = table.getSize();
		drawPixels(colorMap.get(SECTION_TABLE), sectionTableOffset,
				sectionTableSize);
		logger.info("x pixels: " + getXPixels());
		logger.info("y pixels: " + getYPixels());
		logger.info("bytesPerPixel: " + bytesPerPixel());
		Boolean lowAlign = data.getOptionalHeader().isLowAlignmentMode();
		for (SectionHeader header : table.getSectionHeaders()) {
			long sectionOffset = header.getAlignedPointerToRaw(lowAlign);
			logger.info("drawing section to: " + sectionOffset);
			long sectionSize = new SectionLoader(data).getReadSize(header);
			logger.info("drawing section size: " + sectionSize);
			long pixelStart = getPixelNumber(sectionOffset);
			logger.info("pixelStart: " + pixelStart);
			drawPixels(getSectionColor(header), sectionOffset, sectionSize);
		}
	}

	/**
	 * Generate the color of the given section.
	 * 
	 * @param header
	 *            of the section
	 * @return color of the section
	 */
	private Color getSectionColor(SectionHeader header) {
		// color is based on section number
		int nr = header.getNumber();
		Color sectionColor = colorMap.get(SECTION_START);
		// modify the color section number times
		for (int i = 1; i < nr; i++) {
			sectionColor = variate(sectionColor);
		}
		return sectionColor;
	}

	/**
	 * Shift the given section color one step.
	 * 
	 * This creates a color similar to the given color, but still different
	 * enough to tell the new color apart from the old one.
	 * 
	 * @param color
	 * @return modified color
	 */
	private Color variate(Color color) {
		assert color != null;
		final int diff = 30;
		// darken the color for value of diff
		int newRed = shiftColorPart(color.getRed() - diff);
		int newGreen = shiftColorPart(color.getGreen() - diff);
		int newBlue = shiftColorPart(color.getBlue() - diff);
		Color newColor = new Color(newRed, newGreen, newBlue);
		// start at the original section color again if darkening accidentally
		// resulted in black, which has already the meaning of section caves.
		if (newColor.equals(Color.black)) {
			newColor = colorMap.get(SECTION_START);
		}
		return newColor;
	}

	/**
	 * Makes sure that the new integer is within byte range (0 - 255).
	 * 
	 * @param colorPart
	 * @return 255 if the integer is above, returns 0 if it is below, and the
	 *         original value otherwise.
	 */
	private int shiftColorPart(int colorPart) {
		// would be 0, return max value
		if (colorPart < 0) {
			return 255;
		}
		// would be too large --> return 0
		if (colorPart > 255) {
			return 0;
		}

		return colorPart;
	}

	/**
	 * Draws the legend to the Visualizer image.
	 * 
	 * @param withBytePlot
	 *            legend of the byteplot image is added
	 * @param withEntropy
	 *            legend of the entropy image is added
	 * @param withPEStructure
	 *            legend of the PE structure image is added
	 */
	private void drawLegend(boolean withBytePlot, boolean withEntropy,
			boolean withPEStructure) throws IOException {
		int number = 0;
		if (withBytePlot) {
			writeLegendTitle(number++, "BytePlot (left)", Color.lightGray);
			drawLegendEntry(number++, "0xFF", colorMap.get(MAX_BYTE));
			drawLegendEntry(number++, "0x00", colorMap.get(MIN_BYTE));
			drawLegendEntry(number++, "visible ASCII",
					colorMap.get(VISIBLE_ASCII));
			drawLegendEntry(number++, "invisible ASCII",
					colorMap.get(INVISIBLE_ASCII));
			drawLegendEntry(number++, "non-ASCII", colorMap.get(NON_ASCII));
			if (visOverlay != null) {
				drawLegendEntry(number++, "Read Chunks",
						colorMap.get(VISOVERLAY));
			}
		}
		if (withEntropy) {
			String entropyTitle = "Entropy ";
			if (withPEStructure) {
				entropyTitle += "(middle)";
			} else {
				entropyTitle += "(right)";
			}
			writeLegendTitle(number++, entropyTitle, Color.lightGray);
			drawLegendEntry(number++, "0.2 (repetition)",
					getColorForEntropy(0.2));
			drawLegendEntry(number++, "0.5 (code)", getColorForEntropy(0.5));
			drawLegendEntry(number++, "0.8 (packed)", getColorForEntropy(0.8));
			if (visOverlay != null) {
				drawLegendEntry(number++, "Read Chunks",
						colorMap.get(VISOVERLAY), true);
			}
		}
		if (withPEStructure) {
			writeLegendTitle(number++, "PE Structure (right)", Color.lightGray);
			drawLegendEntry(number++, "MSDOS Header",
					colorMap.get(MSDOS_HEADER));
			if(data.maybeGetRichHeader().isPresent()) {
				drawLegendEntry(number++, "Rich Header",
						colorMap.get(RICH_HEADER));
			}
			drawLegendEntry(number++, "COFF File Header",
					colorMap.get(COFF_FILE_HEADER));
			drawLegendEntry(number++, "Optional Header",
					colorMap.get(OPTIONAL_HEADER));
			drawLegendEntry(number++, "Section Table",
					colorMap.get(SECTION_TABLE));
			SectionTable table = data.getSectionTable();
			for (SectionHeader header : table.getSectionHeaders()) {
				Color sectionColor = getSectionColor(header);
				drawLegendEntry(number++, header.getName(), sectionColor);
				sectionColor = variate(sectionColor);
			}

			for (DataDirectoryKey special : specials) {
				SectionLoader loader = new SectionLoader(data);
				Optional<? extends SpecialSection> section = loader
						.maybeLoadSpecialSection(special);
				if (section.isPresent()) {
					specialsAvailability.put(special, true);
					drawLegendEntry(number++, getSpecialsDescription(special),
							getSpecialsColor(special), true);
				}
			}
			// CLR Meta and Streams
			Optional<CLRSection> clr = new SectionLoader(data).maybeLoadCLRSection();
			if(clr.isPresent()){
				CLRSection clrSec = clr.get();
				Color clrColor = colorMap.get(CLR_SECTION);
				drawLegendEntry(number++, "CLR Metadata", clrColor);
				List<StreamHeader> headers = clrSec.metadataRoot().getStreamHeaders();
				Color color = colorMap.get(NET_STREAMS);
				for(StreamHeader header : headers) {
					drawLegendEntry(number++, header.name(), color);
					color = variate(color);
				}
			}
			for (Map.Entry<String, Color> entry : resTypeColors.entrySet()) {
				drawLegendEntry(number++, entry.getKey(), entry.getValue(),
						true);
			}
			if (epAvailable) {
				drawLegendEntry(number++, "Entry Point",
						colorMap.get(ENTRY_POINT), true);
			}
			if (overlayAvailable) {
				drawLegendEntry(number++, "Overlay", colorMap.get(OVERLAY));
			}
			if (visOverlay != null) {
				drawLegendEntry(number++, "Read Chunks",
						colorMap.get(VISOVERLAY), true);
			}
		}
		// drawLegendCrossEntry(number, "Anomalies", anomalyColor);
	}

	private void writeLegendTitle(int number, String description, Color color) {
		assert description != null && color != null;
		int startX = LEGEND_GAP;
		int startY = LEGEND_GAP + (LEGEND_ENTRY_HEIGHT * number);
		if (startY >= height) {
			startX = startX + legendWidth / 2;
			startY = startY - (height);
		}
		int stringX = startX;
		int stringY = startY + LEGEND_SAMPLE_SIZE;
		Graphics g = image.getGraphics();
		g.setColor(color);
		g.drawString(description, stringX, stringY);
		g.drawString("---------------------------------", stringX, stringY
				+ LEGEND_SAMPLE_SIZE);
	}

	// TODO temporary almost-duplicate of drawLegendEntry
	@SuppressWarnings("unused")
	private void drawLegendCrossEntry(int number, String description,
			Color color) {
		assert description != null && color != null;
		int startX = LEGEND_GAP;
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
		int startX = LEGEND_GAP;
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

	/**
	 * Draws a rectangle.
	 * 
	 * @param color
	 *            that fills the rectangle
	 * @param startX
	 *            the x value of the upper left corner for the rectangle
	 * @param startY
	 *            the y value of the upper left corner for the rectangle
	 * @param width
	 *            the width of the rectangle in pixels
	 * @param height
	 *            the height of the rectangle in pixels
	 */
	private void drawRect(Color color, int startX, int startY, int width,
			int height) {
		assert color != null;
		for (int x = startX; x < startX + width; x++) {
			for (int y = startY; y < startY + height; y++) {
				try {
					image.setRGB(x, y, color.getRGB());
				} catch (ArrayIndexOutOfBoundsException e) {
					logger.warn("tried to set x/y = " + x + "/" + y);
				}
			}
		}
	}

	/**
	 * Draws a cross.
	 * 
	 * @param color
	 *            of the cross
	 * @param startX
	 *            the x value of the upper left corner for the cross
	 * @param startY
	 *            the y value of the upper left corner for the cross
	 * @param width
	 *            the width of the cross in pixels
	 * @param height
	 *            the height of the cross in pixels
	 */
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
					logger.warn("tried to set x/y = " + x + "/" + y);
				}
			}
		}
	}

	private void drawCrosses(Color color, long fileOffset, long fileLength) {
		assert color != null;
		long pixelStart = getPixelNumber(fileOffset);
		// necessary to avoid gaps due to rounding issues (you can't just do
		// getPixelNumber(fileLength))
		long pixelLength = getPixelNumber(fileOffset + fileLength) - pixelStart;
		long pixelMax = getXPixels() * getYPixels();
		long pixelEnd = pixelStart + pixelLength;
		if (pixelStart > pixelMax) {
			logger.warn("too many pixels, max is: " + pixelMax
					+ " and trying to set: " + pixelStart);
		} else {
			if (pixelEnd > pixelMax) {
				logger.warn("too many pixels, max is: " + pixelMax
						+ " and trying to set: " + pixelEnd);
				pixelEnd = pixelMax;
			}
			for (long i = pixelStart; i < pixelStart + pixelLength; i++) {
				int x = (int) ((i % getXPixels()) * pixelSize);
				int y = (int) ((i / getXPixels()) * pixelSize);
				int sizemodifier = pixelated ? 2 : 1;
				drawCross(color, x, y, pixelSize * sizemodifier, pixelSize
						* sizemodifier);
			}
		}
	}

	/**
	 * Draws a square pixel at fileOffset with color.
	 * 
	 * @param color
	 *            of the square pixel
	 * @param fileOffset
	 *            file location that the square pixel represents
	 */
	private void drawPixel(Color color, long fileOffset) {
		long size = withMinLength(0);
		drawPixels(color, fileOffset, size);
	}

	/**
	 * Draws a square pixels at fileOffset with color. Height and width of the
	 * drawn area are based on the number of bytes that it represents given by
	 * the length.
	 * 
	 * Square pixels are drawn without visible gap.
	 * 
	 * @param color
	 *            of the square pixels
	 * @param fileOffset
	 *            file location that the square pixels represent
	 * @param length
	 *            number of bytes that are colored by the square pixels.
	 */
	private void drawPixels(Color color, long fileOffset, long length) {
		assert color != null;
		drawPixels(color, fileOffset, length, 0);
	}

	/**
	 * Draws a square pixels at fileOffset with color. Height and width of the
	 * drawn area are based on the number of bytes that it represents given by
	 * the length.
	 * 
	 * @param color
	 *            of the square pixels
	 * @param fileOffset
	 *            file location that the square pixels represent
	 * @param length
	 *            number of bytes that are colored by the square pixels.
	 * @param additionalGap
	 *            the gap between adjacent square pixels
	 */
	private void drawPixels(Color color, long fileOffset, long length,
			int additionalGap) {
		assert color != null;
		long pixelStart = getPixelNumber(fileOffset);
		// necessary to avoid gaps due to rounding issues (you can't just do
		// getPixelNumber(fileLength))
		long pixelLength = getPixelNumber(fileOffset + length) - pixelStart;
		long pixelMax = getXPixels() * getYPixels();
		long pixelEnd = pixelStart + pixelLength;
		if (pixelStart > pixelMax) {
			logger.warn("too many pixels, max is: " + pixelMax
					+ " and trying to set: " + pixelStart);
		} else {
			if (pixelEnd > pixelMax) {
				logger.warn("too many pixels, max is: " + pixelMax
						+ " and trying to set: " + pixelEnd);
				pixelEnd = pixelMax;
			}
			for (long i = pixelStart; i < pixelEnd; i++) {
				int x = (int) ((i % getXPixels()) * pixelSize);
				int y = (int) ((i / getXPixels()) * pixelSize);
				int gap = pixelated ? additionalGap + 1 : additionalGap;
				int sizemodifier = pixelated ? 2 : 1;
				drawRect(color, x + gap, y + gap, pixelSize - gap
						* sizemodifier, pixelSize - gap * sizemodifier);
			}
		}
		// Graphics g = image.getGraphics();
		// g.drawString(new Long(fileOffset).toString(), (pixelStart % xPixels)
		// * pixelSize,(pixelStart / xPixels) * pixelSize );
	}

	// convert fileOffset to square pixels
	private long getPixelNumber(long fileOffset) {
		assert fileOffset >= 0;
		long result = Math.round(fileOffset / bytesPerPixel());
		assert result >= 0;
		return result;
	}

	/**
	 * Calculates how many bytes are covered by one square pixel.
	 *
	 * @return bytes covered by one square pixel
	 */
	private int bytesPerPixel() {
		long pixelMax = getXPixels() * (long) getYPixels();
		// ceil result, because it is a maximum that we use to divide
		return (int) Math.ceil(fileSize / (double) pixelMax);
	}

	/**
	 * For testing purposes only.
	 * 
	 * @param args
	 * @throws IOException
	 */
	public static void main(String[] args) throws IOException {
		VisualizerBuilder builder = new VisualizerBuilder();
		builder.setColor(VISIBLE_ASCII, Color.red);
		builder.setColor(NON_ASCII, Color.green);
		builder.setColor(INVISIBLE_ASCII, Color.orange);
		builder.setColor(ENTROPY, Color.cyan);
		Visualizer vi = builder.build();
		// builder.setFileWidth(400).setHeight(400 - (400 % 8)).setPixelSize(8);
		File folder = new File("C:\\Users\\strup\\Repos\\PortEx\\portextestfiles\\testfiles\\");
		System.out.println("starting to search");
		for (File file : folder.listFiles()) {
			System.out.println("processing file " + file.getAbsolutePath());
			final BufferedImage entropyImage = vi.createEntropyImage(file);
			final BufferedImage bytePlotImage = vi.createBytePlot(file);
			// final BufferedImage structureImage = vi.createImage(file);
			final BufferedImage legendImage = vi.createLegendImage(true, true,
					false);
			BufferedImage joinedImage = ImageUtil.appendImages(bytePlotImage,
					entropyImage);
			// joinedImage = ImageUtil.appendImages(joinedImage,
			// structureImage);
			joinedImage = ImageUtil.appendImages(joinedImage, legendImage);
			ImageIO.write(joinedImage, "png", new File(file.getAbsolutePath()
					+ ".png"));
		}
		// show(joinedImage);
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
		int result = (int) Math.floor(this.fileWidth / (double) this.pixelSize);
		assert result >= 0;
		return result;
	}

	private int getYPixels() {
		int result = (int) Math.ceil(this.height / (double) this.pixelSize);
		assert result >= 0;
		return result;
	}

}
