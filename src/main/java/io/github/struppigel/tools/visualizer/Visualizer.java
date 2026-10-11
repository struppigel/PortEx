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

import io.github.struppigel.parser.FileFormatException;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.PhysicalLocation;
import io.github.struppigel.tools.layout.FileRegion;
import io.github.struppigel.tools.layout.RegionType;
import io.github.struppigel.tools.layout.StructureMap;
import io.github.struppigel.tools.layout.StructureMapBuilder;
import io.github.struppigel.tools.visualizer.VisualizerBuilder.VisualizerSettings;
import io.github.struppigel.tools.visualizer.engine.ByteStatistics;
import io.github.struppigel.tools.visualizer.engine.CachedByteSource;
import io.github.struppigel.tools.visualizer.engine.FileVisualization;
import io.github.struppigel.tools.visualizer.engine.ProgressListener;
import io.github.struppigel.tools.visualizer.engine.ViewMapping;
import io.github.struppigel.tools.visualizer.engine.Viewport;
import io.github.struppigel.tools.visualizer.render.LegendEntry;
import io.github.struppigel.tools.visualizer.render.LegendRenderer;
import io.github.struppigel.tools.visualizer.render.RegionColorScheme;
import io.github.struppigel.tools.visualizer.render.RenderStyle;
import io.github.struppigel.tools.visualizer.render.Track;
import io.github.struppigel.tools.visualizer.render.VisualizerColors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferInt;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static io.github.struppigel.tools.visualizer.ColorableItem.*;

/**
 * Creates images of a file: the structure of a PE file, a byte plot, the
 * local entropy and a legend.
 * <p>
 * The images are drawn by the renderers of
 * {@link io.github.struppigel.tools.visualizer.render}. By default they keep the
 * look of former PortEx versions; {@link VisualizerBuilder#setLegacyStyle(boolean)}
 * switches to the look of the interactive visualization. The structure map
 * and the byte statistics of the last file are kept, so creating several
 * images of the same file parses it once.
 * <p>
 * Pass the PEData if the file is already parsed, e.g.
 * {@link #createImage(PEData)}; the File methods parse the file themselves.
 * The legend only depends on the last file, not on the order of calls.
 *
 * @author Karsten Philipp Boris Hahn
 *
 */
public class Visualizer {

	private static final Logger logger = LogManager.getLogger(Visualizer.class
			.getName());

	private static final int IMAGE_TYPE = BufferedImage.TYPE_INT_RGB;
	private static final String READ_CHUNKS = "Read Chunks";

	private final int additionalGap;
	private final int pixelSize;
	private final boolean pixelated;
	private final int fileWidth;
	private final int height;
	private final int legendWidth;
	private final boolean legacyStyle;
	/** shared with the builder like in former versions */
	private final Map<ColorableItem, Color> colorMap;
	private final List<PhysicalLocation> visOverlay;

	/** the structures and statistics of the last file */
	private Prepared prepared;

	/** what is kept of the last file */
	private static final class Prepared {
		final Object key;
		final File file;
		final StructureMap map;
		final ByteStatistics statistics;
		final FileFormatException notPE;

		Prepared(Object key, File file, StructureMap map, FileFormatException notPE) {
			this.key = key;
			this.file = file;
			this.map = map;
			this.statistics = new ByteStatistics(file);
			this.notPE = notPE;
		}

		boolean isPE() {
			return notPE == null;
		}
	}

	/** identifies a file by path, length and modification time */
	private static final class FileKey {
		final String path;
		final long length;
		final long modified;

		FileKey(File file) {
			this.path = file.getAbsolutePath();
			this.length = file.length();
			this.modified = file.lastModified();
		}

		@Override
		public boolean equals(Object o) {
			if (!(o instanceof FileKey)) return false;
			FileKey that = (FileKey) o;
			return path.equals(that.path) && length == that.length && modified == that.modified;
		}

		@Override
		public int hashCode() {
			return path.hashCode() * 31 + Long.hashCode(length) * 17 + Long.hashCode(modified);
		}
	}

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
		this.legacyStyle = settings.legacyStyle;
		if (settings.pixelated
				&& settings.pixelSize < 2 + settings.additionalGap) {
			this.pixelSize = 2 + settings.additionalGap;
		} else {
			this.pixelSize = settings.pixelSize;
		}
		this.colorMap = settings.colorMap;
	}

	/**
	 * Creates a byte plot of the file. Works for any file.
	 *
	 * @param file
	 *            the file
	 * @return byte plot image
	 * @throws IOException
	 *             if the file can not be read
	 */
	public BufferedImage createBytePlot(File file) throws IOException {
		return createPlot(prepare(file), Track.BYTEPLOT, false);
	}

	/**
	 * Creates a byte plot of a parsed PE file.
	 *
	 * @param data
	 *            the parsed PE file
	 * @return byte plot image
	 * @throws IOException
	 *             if the file can not be read
	 */
	public BufferedImage createBytePlot(PEData data) throws IOException {
		return createPlot(prepare(data), Track.BYTEPLOT, false);
	}

	/**
	 * Creates an image of the local entropies of this file. Works for any
	 * file.
	 *
	 * @param file
	 *            the file
	 * @return image of local entropies
	 * @throws IOException
	 *             if file can not be read
	 */
	public BufferedImage createEntropyImage(File file) throws IOException {
		return createPlot(prepare(file), Track.ENTROPY, true);
	}

	/**
	 * Creates an image of the local entropies of a parsed PE file.
	 *
	 * @param data
	 *            the parsed PE file
	 * @return image of local entropies
	 * @throws IOException
	 *             if the file can not be read
	 */
	public BufferedImage createEntropyImage(PEData data) throws IOException {
		return createPlot(prepare(data), Track.ENTROPY, true);
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
	 * Writes a PNG image to the output file that displays the structure of a
	 * parsed PE file.
	 *
	 * @param data
	 *            the parsed PE file
	 * @param output
	 *            the file to write the image to
	 * @throws IOException
	 *             if the file can not be read
	 */
	public void writeImage(PEData data, File output) throws IOException {
		writeImage(data, output, "png");
	}

	/**
	 * Writes an image to the output file that displays the structure of a
	 * parsed PE file.
	 *
	 * @param data
	 *            the parsed PE file
	 * @param output
	 *            the file to write the image to
	 * @param formatName
	 *            the format name for the output image
	 * @throws IOException
	 *             if the file can not be read
	 */
	public void writeImage(PEData data, File output, String formatName) throws IOException {
		ImageIO.write(createImage(data), formatName, output);
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
	 * @throws FileFormatException
	 *             if the file is not a PE file
	 */
	public BufferedImage createImage(File file) throws IOException {
		Prepared p = prepare(file);
		if (!p.isPE()) {
			throw p.notPE;
		}
		return createStructureImage(p);
	}

	/**
	 * Creates a buffered image that displays the structure of a parsed PE
	 * file.
	 *
	 * @param data
	 *            the parsed PE file
	 * @return buffered image
	 * @throws IOException
	 *             if the file can not be read
	 */
	public BufferedImage createImage(PEData data) throws IOException {
		return createStructureImage(prepare(data));
	}

	/**
	 * Creates a buffered image with a basic Legend. The structure part shows
	 * the structures of the last file an image was created of; it is left out
	 * if there is none or if it is not a PE file.
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
		return LegendRenderer.render(legendEntries(withBytePlot, withEntropy, withPEStructure), legendWidth, height);
	}

	/**
	 * Creates a legend for a parsed PE file.
	 *
	 * @param data
	 *            the parsed PE file
	 * @param withBytePlot
	 *            show byteplot legend
	 * @param withEntropy
	 *            show entropy legend
	 * @param withPEStructure
	 *            show PE structure legend
	 * @return buffered image of the generated legend
	 * @throws IOException
	 *             if the file can not be read
	 */
	public BufferedImage createLegendImage(PEData data, boolean withBytePlot, boolean withEntropy,
			boolean withPEStructure) throws IOException {
		prepare(data);
		return createLegendImage(withBytePlot, withEntropy, withPEStructure);
	}

	/* ------------------------------------------------------------------ */
	/* preparation                                                        */
	/* ------------------------------------------------------------------ */

	private synchronized Prepared prepare(File file) throws IOException {
		FileKey key = new FileKey(file);
		if (prepared != null && key.equals(prepared.key)) {
			return prepared;
		}
		if (!file.isFile()) {
			throw new IOException("not a file: " + file.getAbsolutePath());
		}
		PEData data = null;
		FileFormatException notPE = null;
		try {
			data = PELoader.loadPE(file);
		} catch (FileFormatException e) {
			notPE = e;
		}
		prepared = new Prepared(key, file, mapOf(data, file), notPE);
		return prepared;
	}

	private synchronized Prepared prepare(PEData data) {
		if (prepared != null && prepared.key == data) {
			return prepared;
		}
		prepared = new Prepared(data, data.getFile(), mapOf(data, data.getFile()), null);
		return prepared;
	}

	private StructureMap mapOf(PEData data, File file) {
		if (data == null) {
			return StructureMap.empty(file.length());
		}
		StructureMapBuilder builder = new StructureMapBuilder(data);
		if (visOverlay != null) {
			builder.withCustomRegions(READ_CHUNKS, visOverlay);
		}
		return builder.build();
	}

	/* ------------------------------------------------------------------ */
	/* drawing                                                            */
	/* ------------------------------------------------------------------ */

	private int getXPixels() {
		return Math.max(1, (int) Math.floor(this.fileWidth / (double) this.pixelSize));
	}

	private int getYPixels() {
		return ViewMapping.legacyRows(height, pixelSize);
	}

	private ViewMapping mapping(long fileSize) {
		return ViewMapping.legacy(fileSize, fileWidth, height, pixelSize);
	}

	/** bytes per pixel as double, the minimum structure length of former versions */
	private double minimumLength(long fileSize) {
		return Math.max(1, fileSize / (double) (getXPixels() * (long) getYPixels()));
	}

	private RenderStyle style(long fileSize) {
		if (!legacyStyle) {
			return RenderStyle.defaults().withAdditionalGap(additionalGap).withPixelated(pixelated)
					.withHatchPending(false, 0);
		}
		double minimum = minimumLength(fileSize);
		return RenderStyle.legacy().withAdditionalGap(additionalGap).withPixelated(pixelated)
				.withMinimumRegionLength(minimum).withSampleStep(Math.round(minimum))
				.withLegacyEntropyWindow(Math.max(100, pixelSize)).withHatchPending(false, 0);
	}

	private RegionColorScheme scheme(StructureMap map) {
		return RegionColorScheme.of(map, colorMap,
				legacyStyle ? RegionColorScheme.Mode.LEGACY : RegionColorScheme.Mode.DEFAULT);
	}

	private BufferedImage createPlot(Prepared p, Track track, boolean overlayWithGap) throws IOException {
		if (!legacyStyle) {
			p.statistics.compute(ProgressListener.NONE);
		}
		BufferedImage image = render(p, track);
		drawVisOverlay(image, p.file.length(), overlayWithGap);
		return image;
	}

	private BufferedImage createStructureImage(Prepared p) throws IOException {
		return render(p, Track.STRUCTURE);
	}

	/** draws a track with the mapping of the classic images */
	private BufferedImage render(Prepared p, Track track) throws IOException {
		long fileSize = p.file.length();
		BufferedImage image = new BufferedImage(fileWidth, height, IMAGE_TYPE);
		ViewMapping mapping = mapping(fileSize);
		int rows = getYPixels();
		Viewport viewport = new Viewport(mapping, 0, rows, pixelSize);
		// the rows may exceed the image height, they are cut like before
		int[] buffer = new int[fileWidth * rows * pixelSize];
		try (CachedByteSource source = new CachedByteSource(p.file)) {
			FileVisualization vis = new FileVisualization(p.map, p.statistics, source, scheme(p.map));
			track.renderer().render(vis, viewport, pixelSize, style(fileSize), buffer, fileWidth);
		}
		int[] pixels = ((DataBufferInt) image.getRaster().getDataBuffer()).getData();
		System.arraycopy(buffer, 0, pixels, 0, pixels.length);
		return image;
	}

	/** draws the read chunks on a byte plot or entropy image like former versions */
	private void drawVisOverlay(BufferedImage image, long fileSize, boolean withGap) {
		if (visOverlay == null) {
			return;
		}
		int[] pixels = ((DataBufferInt) image.getRaster().getDataBuffer()).getData();
		long bytesPerPixel = mapping(fileSize).getBytesPerCell();
		double minimum = minimumLength(fileSize);
		long pixelMax = getXPixels() * (long) getYPixels();
		int color = colorOrDefault(VISOVERLAY).getRGB();
		int gap = withGap ? additionalGap : 0;
		for (PhysicalLocation loc : visOverlay) {
			long length = loc.size() < minimum ? Math.round(minimum) : loc.size();
			long start = loc.from() / bytesPerPixel;
			long end = Math.min(pixelMax, (loc.from() + length) / bytesPerPixel);
			for (long i = start; i < end; i++) {
				int x = (int) (i % getXPixels()) * pixelSize;
				int y = (int) (i / getXPixels()) * pixelSize;
				fillCell(pixels, x, y, gap, color);
			}
		}
	}

	private void fillCell(int[] pixels, int x, int y, int gap, int color) {
		int g = pixelated ? gap + 1 : gap;
		int modifier = pixelated ? 2 : 1;
		for (int py = y + g; py < y + pixelSize - g * (modifier - 1) && py < height; py++) {
			for (int px = x + g; px < x + pixelSize - g * (modifier - 1) && px < fileWidth; px++) {
				pixels[py * fileWidth + px] = color;
			}
		}
	}

	private Color colorOrDefault(ColorableItem item) {
		Color color = colorMap.get(item);
		return color != null ? color : VisualizerBuilder.getDefaultColors().get(item);
	}

	/* ------------------------------------------------------------------ */
	/* legend                                                             */
	/* ------------------------------------------------------------------ */

	/** the entries of the legend image, package-private for tests */
	synchronized List<LegendEntry> legendEntries(boolean withBytePlot, boolean withEntropy,
			boolean withPEStructure) {
		StructureMap map = prepared != null && prepared.isPE() ? prepared.map : StructureMap.empty(0);
		RegionColorScheme scheme = scheme(map);
		boolean structure = withPEStructure && prepared != null && prepared.isPE();
		if (!legacyStyle) {
			List<LegendEntry> entries = new ArrayList<>(LegendRenderer.entries(map, scheme, withBytePlot,
					withEntropy, structure ? RenderStyle.defaults().getPaintedTypes()
							: Collections.<RegionType>emptySet()));
			return entries;
		}
		List<LegendEntry> entries = new ArrayList<>();
		if (withBytePlot) {
			entries.add(LegendEntry.title("BytePlot (left)"));
			entries.add(LegendEntry.entry("0xFF", colorOrDefault(MAX_BYTE), false));
			entries.add(LegendEntry.entry("0x00", colorOrDefault(MIN_BYTE), false));
			entries.add(LegendEntry.entry("visible ASCII", colorOrDefault(VISIBLE_ASCII), false));
			entries.add(LegendEntry.entry("invisible ASCII", colorOrDefault(INVISIBLE_ASCII), false));
			entries.add(LegendEntry.entry("non-ASCII", colorOrDefault(NON_ASCII), false));
			if (visOverlay != null) {
				entries.add(LegendEntry.entry(READ_CHUNKS, colorOrDefault(VISOVERLAY), false));
			}
		}
		if (withEntropy) {
			entries.add(LegendEntry.title("Entropy " + (withPEStructure ? "(middle)" : "(right)")));
			Color entropy = colorOrDefault(ENTROPY);
			entries.add(LegendEntry.entry("0.2 (repetition)", VisualizerColors.entropyColor(entropy, 0.2), false));
			entries.add(LegendEntry.entry("0.5 (code)", VisualizerColors.entropyColor(entropy, 0.5), false));
			entries.add(LegendEntry.entry("0.8 (packed)", VisualizerColors.entropyColor(entropy, 0.8), false));
			if (visOverlay != null) {
				entries.add(LegendEntry.entry(READ_CHUNKS, colorOrDefault(VISOVERLAY), true));
			}
		}
		if (structure) {
			entries.addAll(legacyStructureEntries(map, scheme));
		}
		return entries;
	}

	/** the structure entries of former versions, for the structures of the map */
	private List<LegendEntry> legacyStructureEntries(StructureMap map, RegionColorScheme scheme) {
		List<LegendEntry> entries = new ArrayList<>();
		entries.add(LegendEntry.title("PE Structure (right)"));
		entries.add(LegendEntry.entry("MSDOS Header", colorOrDefault(MSDOS_HEADER), false));
		if (!map.getRegions(RegionType.RICH_HEADER).isEmpty()) {
			entries.add(LegendEntry.entry("Rich Header", colorOrDefault(RICH_HEADER), false));
		}
		entries.add(LegendEntry.entry("COFF File Header", colorOrDefault(COFF_FILE_HEADER), false));
		entries.add(LegendEntry.entry("Optional Header", colorOrDefault(OPTIONAL_HEADER), false));
		entries.add(LegendEntry.entry("Section Table", colorOrDefault(SECTION_TABLE), false));
		Color sectionStart = colorOrDefault(SECTION_START);
		for (FileRegion header : map.getRegions(RegionType.SECTION_HEADER)) {
			int number = Integer.parseInt(header.getAttributes().get(FileRegion.ATTR_SECTION_NUMBER));
			entries.add(LegendEntry.entry(header.getAttributes().get(FileRegion.ATTR_SECTION_NAME),
					VisualizerColors.variate(sectionStart, sectionStart, number - 1), false));
		}
		RegionType[] specials = {RegionType.RESOURCE_DIRECTORY, RegionType.IMPORT_SECTION,
				RegionType.DELAY_IMPORT_SECTION, RegionType.EXPORT_SECTION, RegionType.RELOCATION,
				RegionType.DEBUG_DIRECTORY};
		for (RegionType special : specials) {
			if (!map.getRegions(special).isEmpty()) {
				ColorableItem item = special.getColorableItem();
				entries.add(LegendEntry.entry(item.getLegendDescription(), colorOrDefault(item), true));
			}
		}
		if (!map.getRegions(RegionType.CLR_HEADER).isEmpty()) {
			entries.add(LegendEntry.entry("CLR Metadata", colorOrDefault(CLR_SECTION), false));
			for (FileRegion stream : map.getRegions(RegionType.CLR_STREAM)) {
				entries.add(LegendEntry.entry(stream.getName(), scheme.colorOf(stream), false));
			}
		}
		for (Map.Entry<String, Color> e : scheme.getResourceTypeColors().entrySet()) {
			entries.add(LegendEntry.entry(e.getKey(), e.getValue(), true));
		}
		if (!map.getRegions(RegionType.ENTRY_POINT).isEmpty()) {
			entries.add(LegendEntry.entry("Entry Point", colorOrDefault(ENTRY_POINT), true));
		}
		if (!map.getRegions(RegionType.OVERLAY).isEmpty()) {
			entries.add(LegendEntry.entry("Overlay", colorOrDefault(OVERLAY), false));
		}
		if (visOverlay != null) {
			entries.add(LegendEntry.entry(READ_CHUNKS, colorOrDefault(VISOVERLAY), true));
		}
		return entries;
	}

	/**
	 * Writes byte plot, entropy and legend images of a file or of each file in
	 * a folder next to the files.
	 *
	 * @param args
	 *            a file or folder
	 * @throws IOException
	 *             if a file can not be read or written
	 */
	public static void main(String[] args) throws IOException {
		if (args.length < 1) {
			System.out.println("usage: Visualizer <file or folder>");
			return;
		}
		Visualizer vi = new VisualizerBuilder().build();
		File input = new File(args[0]);
		File[] files = input.isDirectory() ? input.listFiles() : new File[]{input};
		if (files == null) {
			return;
		}
		for (File file : files) {
			if (!file.isFile()) {
				continue;
			}
			logger.info("processing file " + file.getAbsolutePath());
			BufferedImage joinedImage = ImageUtil.appendImages(vi.createBytePlot(file),
					vi.createEntropyImage(file));
			joinedImage = ImageUtil.appendImages(joinedImage, vi.createLegendImage(true, true, false));
			ImageIO.write(joinedImage, "png", new File(file.getAbsolutePath() + ".png"));
		}
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

	/**
	 * @return true if the images keep the look of former PortEx versions
	 */
	public boolean isLegacyStyle() {
		return legacyStyle;
	}
}
