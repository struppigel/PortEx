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
package io.github.struppigel.tools.visualizer;

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.FileFormatException;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.PhysicalLocation;
import io.github.struppigel.tools.layout.RegionType;
import io.github.struppigel.tools.layout.StructureMap;
import io.github.struppigel.tools.visualizer.render.LegendEntry;
import io.github.struppigel.tools.visualizer.render.RegionColorScheme;
import org.testng.annotations.Test;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.*;

public class VisualizerTest {

    private static final String[] SAMPLES = {"WinRar.exe", "HelloWorld.exe", "embedded_exe_overlay",
            "embedded_exe_resources", "upx.exe", "Lab11-02dll", "strings.exe"};

    /** fileWidth, height, pixelSize, additionalGap, pixelated */
    private static final int[][] SETTINGS = {{300, 600, 5, 1, 0}, {256, 1000, 4, 1, 0}, {180, 500, 5, 1, 0},
            {600, 800, 10, 3, 1}, {301, 333, 7, 2, 0}};

    private static File sample(String name) {
        return new File(TestreportsReader.RESOURCE_DIR + TestreportsReader.TEST_FILE_DIR + "/" + name);
    }

    private static VisualizerBuilder builder(int[] s) {
        return new VisualizerBuilder().setFileWidth(s[0]).setHeight(s[1]).setPixelSize(s[2])
                .setAdditionalGap(s[3]).setPixelated(s[4] == 1);
    }

    private static LegacyVisualizerReference reference(int[] s) {
        VisualizerBuilder.VisualizerSettings settings = new VisualizerBuilder.VisualizerSettings();
        settings.fileWidth = s[0];
        settings.height = s[1];
        settings.pixelSize = s[2];
        settings.additionalGap = s[3];
        settings.pixelated = s[4] == 1;
        return new LegacyVisualizerReference(settings);
    }

    /** the percentage of equal pixels, -1 if the sizes differ */
    private static double samePixels(BufferedImage a, BufferedImage b) {
        if (a.getWidth() != b.getWidth() || a.getHeight() != b.getHeight()) {
            return -1;
        }
        long same = 0;
        for (int y = 0; y < a.getHeight(); y++) {
            for (int x = 0; x < a.getWidth(); x++) {
                if ((a.getRGB(x, y) & 0xFFFFFF) == (b.getRGB(x, y) & 0xFFFFFF)) {
                    same++;
                }
            }
        }
        return same * 100.0 / (a.getWidth() * (long) a.getHeight());
    }

    private static void assertSameSize(BufferedImage actual, BufferedImage expected) {
        assertEquals(actual.getWidth(), expected.getWidth());
        assertEquals(actual.getHeight(), expected.getHeight());
    }

    @Test
    public void defaultLookMatchesFormerVersions() throws IOException {
        for (int[] s : SETTINGS) {
            for (String name : SAMPLES) {
                File file = sample(name);
                Visualizer visualizer = builder(s).build();
                LegacyVisualizerReference reference = reference(s);
                String message = name + " " + Arrays.toString(s);
                BufferedImage structure = visualizer.createImage(file);
                BufferedImage oldStructure = reference.createImage(file);
                assertSameSize(structure, oldStructure);
                // the PE signature and the stub are not colored in the legacy look; differences come from
                // fixed locations, e.g. of .NET stream headers
                assertTrue(samePixels(structure, oldStructure) > 99.5, message + " structure "
                        + samePixels(structure, oldStructure));
                BufferedImage bytePlot = visualizer.createBytePlot(file);
                assertEquals(samePixels(bytePlot, reference.createBytePlot(file)), 100.0, message + " byte plot");
                // the former versions drew one pixel after the end of the file
                BufferedImage entropy = visualizer.createEntropyImage(file);
                assertTrue(samePixels(entropy, reference.createEntropyImage(file)) > 99.9, message + " entropy");
                // the former legend depended on the call order, compare after createImage
                visualizer.createImage(file);
                reference.createImage(file);
                assertSameSize(visualizer.createLegendImage(true, true, true),
                        reference.createLegendImage(true, true, true));
            }
        }
    }

    @Test
    public void newLookKeepsDimensions() throws IOException {
        for (int[] s : SETTINGS) {
            File file = sample("WinRar.exe");
            Visualizer visualizer = builder(s).setLegacyStyle(false).build();
            assertFalse(visualizer.isLegacyStyle());
            LegacyVisualizerReference reference = reference(s);
            assertSameSize(visualizer.createImage(file), reference.createImage(file));
            assertSameSize(visualizer.createBytePlot(file), reference.createBytePlot(file));
            assertSameSize(visualizer.createEntropyImage(file), reference.createEntropyImage(file));
            assertSameSize(visualizer.createLegendImage(true, true, true),
                    reference.createLegendImage(true, true, true));
        }
    }

    @Test
    public void newLookColorsThePESignature() throws IOException {
        File file = sample("WinRar.exe");
        PEData data = PELoader.loadPE(file);
        // one byte per pixel, so that the signature has its own pixels
        Visualizer visualizer = new VisualizerBuilder().setLegacyStyle(false).setPixelSize(1).setFileWidth(64)
                .setBytesPerPixel(1, file.length()).build();
        BufferedImage image = visualizer.createImage(data);
        long peSig = data.getPESignature().getOffset();
        StructureMap map = StructureMap.of(data);
        int expected = RegionColorScheme.of(map).colorOf(map.getRegions(RegionType.PE_SIGNATURE).get(0)).getRGB();
        assertEquals(image.getRGB((int) (peSig % 64), (int) (peSig / 64)), expected);
    }

    @Test
    public void fileAndPEDataGiveTheSameImages() throws IOException {
        for (boolean legacy : new boolean[]{true, false}) {
            for (String name : new String[]{"WinRar.exe", "HelloWorld.exe"}) {
                File file = sample(name);
                PEData data = PELoader.loadPE(file);
                Visualizer a = new VisualizerBuilder().setLegacyStyle(legacy).build();
                Visualizer b = new VisualizerBuilder().setLegacyStyle(legacy).build();
                assertEquals(samePixels(a.createImage(file), b.createImage(data)), 100.0, name);
                assertEquals(samePixels(a.createBytePlot(file), b.createBytePlot(data)), 100.0, name);
                assertEquals(samePixels(a.createEntropyImage(file), b.createEntropyImage(data)), 100.0, name);
                assertEquals(samePixels(a.createLegendImage(true, true, true),
                        b.createLegendImage(data, true, true, true)), 100.0, name);
            }
        }
    }

    private static List<String> labels(List<LegendEntry> entries) {
        List<String> labels = new ArrayList<>();
        for (LegendEntry entry : entries) {
            labels.add(entry.getLabel());
        }
        return labels;
    }

    @Test
    public void legendDoesNotDependOnCallOrder() throws IOException {
        File file = sample("WinRar.exe");
        Visualizer visualizer = new VisualizerBuilder().build();
        visualizer.createImage(file);
        visualizer.createEntropyImage(file);
        visualizer.createBytePlot(file);
        List<String> labels = labels(visualizer.legendEntries(true, true, true));
        assertTrue(labels.contains("Entry Point"), labels.toString());
        assertTrue(labels.contains("Overlay"), labels.toString());
        Visualizer fresh = new VisualizerBuilder().build();
        fresh.createBytePlot(file);
        assertEquals(labels(fresh.legendEntries(true, true, true)), labels);
    }

    @Test
    public void resourceTypesDoNotLeakIntoTheNextFile() throws IOException {
        Visualizer visualizer = new VisualizerBuilder().build();
        visualizer.createImage(sample("WinRar.exe"));
        assertTrue(labels(visualizer.legendEntries(false, false, true)).contains("RT_DIALOG"));
        visualizer.createImage(sample("HelloWorld.exe"));
        List<String> labels = labels(visualizer.legendEntries(false, false, true));
        assertFalse(labels.contains("RT_DIALOG"), labels.toString());
        assertTrue(labels.contains("RT_VERSION"), labels.toString());
    }

    @Test
    public void legendWithoutFileHasOnlyPlotEntries() throws IOException {
        Visualizer visualizer = new VisualizerBuilder().build();
        BufferedImage legend = visualizer.createLegendImage(true, true, true);
        assertEquals(legend.getWidth(), VisualizerBuilder.DEFAULT_LEGEND_WIDTH);
        List<String> labels = labels(visualizer.legendEntries(true, true, true));
        assertTrue(labels.contains("BytePlot (left)"));
        assertFalse(labels.contains("PE Structure (right)"));
    }

    @Test
    public void emptyAndNonPEFiles() throws IOException {
        File empty = File.createTempFile("portex-visualizer-empty", ".bin");
        File text = File.createTempFile("portex-visualizer-text", ".txt");
        try {
            Files.write(text.toPath(), "no PE file, just some text".getBytes("ASCII"));
            Visualizer visualizer = new VisualizerBuilder().build();
            for (File file : new File[]{empty, text}) {
                assertEquals(visualizer.createBytePlot(file).getHeight(), VisualizerBuilder.DEFAULT_HEIGHT);
                assertEquals(visualizer.createEntropyImage(file).getWidth(), VisualizerBuilder.DEFAULT_FILE_WIDTH);
                assertNotNull(visualizer.createLegendImage(true, true, true));
                try {
                    visualizer.createImage(file);
                    fail("expected FileFormatException");
                } catch (FileFormatException expected) {
                }
            }
            Visualizer newLook = new VisualizerBuilder().setLegacyStyle(false).build();
            assertNotNull(newLook.createEntropyImage(empty));
            assertNotNull(newLook.createBytePlot(text));
        } finally {
            empty.delete();
            text.delete();
        }
    }

    @Test
    public void readChunksAreDrawn() throws IOException {
        File file = sample("WinRar.exe");
        List<PhysicalLocation> chunks = Arrays.asList(new PhysicalLocation(0x20000, 0x8000));
        VisualizerBuilder.VisualizerSettings settings = new VisualizerBuilder.VisualizerSettings();
        settings.visOverlay = chunks;
        LegacyVisualizerReference reference = new LegacyVisualizerReference(settings);
        Visualizer visualizer = new VisualizerBuilder().setVisOverlay(chunks).build();
        assertEquals(samePixels(visualizer.createBytePlot(file), reference.createBytePlot(file)), 100.0);
        assertTrue(samePixels(visualizer.createImage(file), reference.createImage(file)) > 99.5);
        assertTrue(labels(visualizer.legendEntries(true, false, true)).contains("Read Chunks"));
    }

    @Test
    public void writesImages() throws IOException {
        File file = sample("HelloWorld.exe");
        File out = File.createTempFile("portex-visualizer", ".png");
        try {
            Visualizer visualizer = new VisualizerBuilder().build();
            visualizer.writeImage(PELoader.loadPE(file), out);
            assertTrue(out.length() > 0);
            visualizer.writeImage(file, out, "png");
            assertTrue(out.length() > 0);
        } finally {
            out.delete();
        }
    }
}
