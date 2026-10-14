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

import io.github.struppigel.parser.PhysicalLocation;
import io.github.struppigel.parser.Preconditions;

import java.awt.*;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static io.github.struppigel.tools.visualizer.ColorableItem.*;

/**
 * Builds a visualizer based on properties like the height of the image.
 * 
 * @author Karsten Philipp Boris Hahn
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
	public static final int DEFAULT_LEGEND_WIDTH = 300;
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

	/**
	 * By default, images keep the look of former PortEx versions.
	 */
	public static final boolean DEFAULT_LEGACY_STYLE = true;

	/* Default header colors */
	private static final Color DEFAULT_MSDOS_COLOR = new Color(0, 0, 200);
	private static final Color DEFAULT_RICH_COLOR = new Color(120,80,75);
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
	private static final Color DEFAULT_NET_STREAMS_COLOR = new Color(255, 198, 226);
	private static final Color DEFAULT_CLR_METADATA_COLOR = new Color(40,184,232 );
	
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

	/* Structure map colors */
	private static final Color DEFAULT_PE_SIGNATURE_COLOR = new Color(255, 120, 0);
	private static final Color DEFAULT_MSDOS_STUB_COLOR = new Color(90, 90, 160);
	private static final Color DEFAULT_BOUND_IMPORT_COLOR = new Color(200, 200, 120);
	private static final Color DEFAULT_EXCEPTION_COLOR = new Color(160, 60, 60);
	private static final Color DEFAULT_CERTIFICATE_COLOR = new Color(230, 190, 90);
	private static final Color DEFAULT_TLS_COLOR = new Color(0, 160, 160);
	private static final Color DEFAULT_LOAD_CONFIG_COLOR = new Color(140, 140, 40);
	private static final Color DEFAULT_UNMAPPED_COLOR = new Color(48, 48, 48);
	private static final Color DEFAULT_SIGNATURE_MATCH_COLOR = new Color(0, 230, 230);

	private final VisualizerSettings settings = new VisualizerSettings();

	/**
	 * Data object to pass settings for the visualizer in one parameter.
	 * 
	 * @author Karsten Philipp Boris Hahn
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
		public boolean legacyStyle = DEFAULT_LEGACY_STYLE;

		public VisualizerSettings() {
			initDefaultColorMap();
		}

		private void initDefaultColorMap() {
			colorMap = new EnumMap<>(ColorableItem.class);
			/* Header */
			colorMap.put(ColorableItem.MSDOS_HEADER, DEFAULT_MSDOS_COLOR);
			colorMap.put(ColorableItem.RICH_HEADER, DEFAULT_RICH_COLOR);
			colorMap.put(ColorableItem.COFF_FILE_HEADER, DEFAULT_COFF_HEADER_COLOR);
			colorMap.put(ColorableItem.OPTIONAL_HEADER, DEFAULT_OPTIONAL_HEADER_COLOR);
			colorMap.put(ColorableItem.SECTION_TABLE, DEFAULT_SECTION_TABLE_COLOR);
			/* Special Sections */
			colorMap.put(ColorableItem.IMPORT_SECTION, DEFAULT_IMPORT_COLOR);
			colorMap.put(ColorableItem.EXPORT_SECTION, DEFAULT_EXPORT_COLOR);
			colorMap.put(ColorableItem.RESOURCE_SECTION, DEFAULT_RSRC_COLOR);
			colorMap.put(ColorableItem.RELOC_SECTION, DEFAULT_RELOC_COLOR);
			colorMap.put(ColorableItem.DELAY_IMPORT_SECTION, DEFAULT_DELAY_IMPORT_COLOR);
			/* Everything .NET */
			colorMap.put(ColorableItem.CLR_SECTION, DEFAULT_CLR_METADATA_COLOR);
			colorMap.put(ColorableItem.NET_STREAMS, DEFAULT_NET_STREAMS_COLOR);
			/* Other */
			colorMap.put(ColorableItem.DEBUG_SECTION, DEFAULT_DEBUG_COLOR);
			colorMap.put(ColorableItem.OVERLAY, DEFAULT_OVERLAY_COLOR);
			colorMap.put(ColorableItem.ENTRY_POINT, DEFAULT_ENTRY_POINT_COLOR);
			colorMap.put(ColorableItem.SECTION_START, DEFAULT_SECTION_START_COLOR);
			colorMap.put(ColorableItem.ANOMALY, DEFAULT_ANOMALY_COLOR);
			/* BytePlot colors */
			colorMap.put(ColorableItem.VISIBLE_ASCII, DEFAULT_VISIBLE_ASCII_COLOR);
			colorMap.put(ColorableItem.INVISIBLE_ASCII, DEFAULT_INVISIBLE_ASCII_COLOR);
			colorMap.put(ColorableItem.MAX_BYTE, DEFAULT_MAX_BYTE_COLOR);
			colorMap.put(ColorableItem.MIN_BYTE, DEFAULT_MIN_BYTE_COLOR);
			colorMap.put(ColorableItem.NON_ASCII, DEFAULT_NON_ASCII_COLOR);
			/* Entropy colors */
			colorMap.put(ColorableItem.ENTROPY, DEFAULT_ENTROPY_COLOR);
			/* VisOverlay color */
			colorMap.put(ColorableItem.VISOVERLAY, DEFAULT_VISOVERLAY_COLOR);
			/* Structure map colors */
			colorMap.put(ColorableItem.PE_SIGNATURE, DEFAULT_PE_SIGNATURE_COLOR);
			colorMap.put(ColorableItem.MSDOS_STUB, DEFAULT_MSDOS_STUB_COLOR);
			colorMap.put(ColorableItem.BOUND_IMPORT_SECTION, DEFAULT_BOUND_IMPORT_COLOR);
			colorMap.put(ColorableItem.EXCEPTION_SECTION, DEFAULT_EXCEPTION_COLOR);
			colorMap.put(ColorableItem.CERTIFICATE_TABLE, DEFAULT_CERTIFICATE_COLOR);
			colorMap.put(ColorableItem.TLS_SECTION, DEFAULT_TLS_COLOR);
			colorMap.put(ColorableItem.LOAD_CONFIG_SECTION, DEFAULT_LOAD_CONFIG_COLOR);
			colorMap.put(ColorableItem.UNMAPPED, DEFAULT_UNMAPPED_COLOR);
			colorMap.put(ColorableItem.SIGNATURE_MATCH, DEFAULT_SIGNATURE_MATCH_COLOR);
		}
	}

	/**
	 * Returns the default colors of all colorable items.
	 *
	 * @return a new, modifiable map of the default colors
	 */
	public static Map<ColorableItem, Color> getDefaultColors() {
		return new EnumMap<>(new VisualizerSettings().colorMap);
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
	 * Sets whether the images keep the look of former PortEx versions, which
	 * is the default. With false, the images use the look of the interactive
	 * visualization: each byte plot pixel shows the dominant byte class of its
	 * bytes, the entropy is the mean of 256 byte windows, smaller structures
	 * are drawn on top of larger ones and all known structures are colored,
	 * e.g. the PE signature and the MSDOS stub. The image size and the
	 * position of each structure stay the same.
	 *
	 * @param legacyStyle
	 *            true to keep the look of former versions
	 * @return this VisualizerBuilder
	 */
	public VisualizerBuilder setLegacyStyle(boolean legacyStyle) {
		settings.legacyStyle = legacyStyle;
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
