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

import static com.github.katjahahn.tools.visualizer.ColorableItem.*;

import java.awt.Color;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import com.github.katjahahn.parser.PhysicalLocation;
import com.google.common.base.Preconditions;

/**
 * Builds a visualizer based on properties like the height of the image.
 * 
 * @author Katja Hahn
 * 
 */
public class VisualizerBuilder {

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

	/* Default header colors */
	private static final Color DEFAULT_MSDOS_COLOR = new Color(0, 0, 200);
	private static final Color DEFAULT_COFF_HEADER_COLOR = new Color(0, 200, 0);
	private static final Color DEFAULT_OPTIONAL_HEADER_COLOR = new Color(200,
			0, 0);
	private static final Color DEFAULT_SECTION_TABLE_COLOR = new Color(200,
			200, 0);
	
	/* Default special section colors */
	private static final Color DEFAULT_IMPORT_COLOR = new Color(250, 250, 80);
	private static final Color DEFAULT_EXPORT_COLOR = new Color(220, 80, 220);
	private static final Color DEFAULT_RSRC_COLOR = new Color(100, 250, 100);
	private static final Color DEFAULT_DEBUG_COLOR = new Color(0, 0, 220);
	private static final Color DEFAULT_RELOC_COLOR = new Color(100, 10, 220);
	private static final Color DEFAULT_DELAY_IMPORT_COLOR = new Color(220, 100,
			0);
	
	/* Other colors */
	private static final Color DEFAULT_ENTRY_POINT_COLOR = new Color(255, 80,
			80);
	private static final Color DEFAULT_SECTION_START_COLOR = new Color(220,
			220, 220);
	private static final Color DEFAULT_OVERLAY_COLOR = new Color(100, 100, 240);
	private static final Color DEFAULT_ANOMALY_COLOR = new Color(255, 255, 255);

	/* BytePlot colors */
	private static final Color DEFAULT_MIN_BYTE_COLOR = Color.black;
	private static final Color DEFAULT_MAX_BYTE_COLOR = Color.white;
	private static final Color DEFAULT_VISIBLE_ASCII_COLOR = Color.blue;
	private static final Color DEFAULT_INVISIBLE_ASCII_COLOR = Color.green;
	private static final Color DEFAULT_NON_ASCII_COLOR = Color.yellow;

	/* Entropy color */ //TODO implement
	private static final Color DEFAULT_ENTROPY_COLOR = new Color(0, 0, 0);
	
	/* VisOverlay color */ 
	private static final Color DEFAULT_VISOVERLAY_COLOR = Color.magenta;

	private final VisualizerSettings settings = new VisualizerSettings();

	/**
	 * Data object to pass settings for the visualizer in one parameter.
	 * 
	 * @author Katja Hahn
	 *
	 */
	static class VisualizerSettings {
		public int additionalGap = DEFAULT_ADDITIONAL_GAP;
		public int pixelSize = DEFAULT_PIXEL_SIZE;
		public boolean pixelated = DEFAULT_PIXELATED;
		public int fileWidth = DEFAULT_FILE_WIDTH;
		public int height = DEFAULT_HEIGHT;
		public int legendWidth = DEFAULT_LEGEND_WIDTH;
		public Map<ColorableItem, Color> colorMap;
		public List<PhysicalLocation> visOverlay;

		public VisualizerSettings() {
			initDefaultColorMap();
		}

		private void initDefaultColorMap() {
			colorMap = new EnumMap<>(ColorableItem.class);
			/* Header */
			colorMap.put(MSDOS_HEADER, DEFAULT_MSDOS_COLOR);
			colorMap.put(COFF_FILE_HEADER, DEFAULT_COFF_HEADER_COLOR);
			colorMap.put(OPTIONAL_HEADER, DEFAULT_OPTIONAL_HEADER_COLOR);
			colorMap.put(SECTION_TABLE, DEFAULT_SECTION_TABLE_COLOR);
			/* Special Sections */
			colorMap.put(IMPORT_SECTION, DEFAULT_IMPORT_COLOR);
			colorMap.put(EXPORT_SECTION, DEFAULT_EXPORT_COLOR);
			colorMap.put(RESOURCE_SECTION, DEFAULT_RSRC_COLOR);
			colorMap.put(RELOC_SECTION, DEFAULT_RELOC_COLOR);
			colorMap.put(DELAY_IMPORT_SECTION, DEFAULT_DELAY_IMPORT_COLOR);
			/* Other */
			colorMap.put(DEBUG_SECTION, DEFAULT_DEBUG_COLOR);
			colorMap.put(OVERLAY, DEFAULT_OVERLAY_COLOR);
			colorMap.put(ENTRY_POINT, DEFAULT_ENTRY_POINT_COLOR);
			colorMap.put(SECTION_START, DEFAULT_SECTION_START_COLOR);
			colorMap.put(ANOMALY, DEFAULT_ANOMALY_COLOR);
			/* BytePlot colors */
			colorMap.put(VISIBLE_ASCII, DEFAULT_VISIBLE_ASCII_COLOR);
			colorMap.put(INVISIBLE_ASCII, DEFAULT_INVISIBLE_ASCII_COLOR);
			colorMap.put(MAX_BYTE, DEFAULT_MAX_BYTE_COLOR);
			colorMap.put(MIN_BYTE, DEFAULT_MIN_BYTE_COLOR);
			colorMap.put(NON_ASCII, DEFAULT_NON_ASCII_COLOR);
			/* Entropy colors */
			colorMap.put(ENTROPY, DEFAULT_ENTROPY_COLOR);
			/* VisOverlay color */
			colorMap.put(VISOVERLAY, DEFAULT_VISOVERLAY_COLOR);
		}
	}

	/**
	 * Build the visualizer with all settings made.
	 * 
	 * @return the visualizer
	 */
	public Visualizer build() {
		return new Visualizer(settings);
	}

	/**
	 * Sets the color for a colorable item.
	 * 
	 * @param key
	 *            the item to be colored
	 * @param color
	 *            the color of the item
	 * @return this VisualizerBuilder
	 */
	public VisualizerBuilder setColor(ColorableItem key, Color color) {
		settings.colorMap.put(key, color);
		return this;
	}

	/**
	 * Sets the width of the legend.
	 * <p>
	 * Affects only the available space, not font size or similar.
	 * 
	 * @param legendWidth
	 * @return this VisualizerBuilder
	 */
	public VisualizerBuilder setLegendWidth(int legendWidth) {
		Preconditions.checkArgument(legendWidth >= 0);
		settings.legendWidth = legendWidth;
		return this;
	}

	/**
	 * Sets the height of the resulting image, thus also the height of the PE
	 * file representation.
	 * 
	 * @param height
	 * @return this VisualizerBuilder
	 */
	public VisualizerBuilder setHeight(int height) {
		Preconditions.checkArgument(height > 0);
		settings.height = height;
		return this;
	}

	/**
	 * Sets the width of the PE file representation in (real) pixels.
	 * 
	 * @param fileWidth
	 * @return this VisualizerBuilder
	 */
	public VisualizerBuilder setFileWidth(int fileWidth) {
		Preconditions.checkArgument(fileWidth > 0);
		settings.fileWidth = fileWidth;
		return this;
	}

	/**
	 * Sets pixelated mode, meaning every square pixel in the image has borders
	 * if true.
	 * 
	 * @param pixelated
	 * @return this VisualizerBuilder
	 */
	public VisualizerBuilder setPixelated(boolean pixelated) {
		settings.pixelated = pixelated;
		return this;
	}

	/**
	 * Sets the length and width of one square pixel.
	 * 
	 * @param pixelSize
	 * @return this VisualizerBuilder
	 */
	public VisualizerBuilder setPixelSize(int pixelSize) {
		Preconditions.checkArgument(pixelSize > 0);
		settings.pixelSize = pixelSize;
		return this;
	}
	
	public VisualizerBuilder setVisOverlay(List<PhysicalLocation> visOverlay) {
		Preconditions.checkNotNull(visOverlay);
		settings.visOverlay = visOverlay;
		return this;
	}

	/**
	 * Sets the reduced size on each side of square pixels that lie on top of
	 * others.
	 * 
	 * @param additionalGap
	 * @return this VisualizerBuilder
	 */
	public VisualizerBuilder setAdditionalGap(int additionalGap) {
		Preconditions.checkArgument(additionalGap >= 0);
		settings.additionalGap = additionalGap;
		return this;
	}

	/**
	 * Sets the number of file bytes that are represented by one square pixel.
	 * The height of the image is changed accordingly.
	 * 
	 * @param bytes
	 *            bytes to be set per pixel
	 * @param fileLength
	 *            the length of the file
	 * @return this VisualizerBuilder
	 */
	// TODO maybe calculate with filelength in visualizer
	public VisualizerBuilder setBytesPerPixel(int bytes, long fileLength) {
		Preconditions.checkArgument(bytes > 0);
		double nrOfPixels = fileLength / (double) bytes;
		double pixelsPerRow = Math.floor(settings.fileWidth
				/ (double) settings.pixelSize);
		double pixelsPerCol = Math.ceil(nrOfPixels / (double) pixelsPerRow);
		settings.height = (int) Math.ceil(pixelsPerCol * settings.pixelSize);
		return this;
	}
}
