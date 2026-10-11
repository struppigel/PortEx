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

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.tools.layout.StructureMap;
import io.github.struppigel.tools.visualizer.render.RegionColorScheme;
import io.github.struppigel.tools.visualizer.render.RenderStyle;
import io.github.struppigel.tools.visualizer.render.Track;
import org.testng.SkipException;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.util.Random;

import static org.testng.Assert.assertTrue;

/**
 * Benchmarks of the visualization engine on large samples. Run with
 * {@code .\test.ps1 -Perf}. The limits are about three times the budget of
 * the design, so that slow machines do not fail.
 */
public class VisualizationPerfTest {

    private static final String[] LARGE_SAMPLES = {"DotNetBundle.exe", "WMIX.exe"};

    private static File sample(String name) {
        File file = new File(TestreportsReader.RESOURCE_DIR + TestreportsReader.TEST_FILE_DIR + "/" + name);
        if (!file.isFile()) {
            throw new SkipException("sample not available: " + file);
        }
        return file;
    }

    private static double millis(long nanos) {
        return nanos / 1e6;
    }

    @Test(groups = "performance")
    public void byteStatisticsPer100MB() throws IOException {
        for (String name : LARGE_SAMPLES) {
            File file = sample(name);
            new ByteStatistics(file).compute(ProgressListener.NONE); // warm up file cache and JIT
            long start = System.nanoTime();
            ByteStatistics stats = new ByteStatistics(file);
            stats.compute(ProgressListener.NONE);
            double ms = millis(System.nanoTime() - start);
            double per100MB = ms / (file.length() / 100e6);
            System.out.printf("ByteStatistics %s (%d MB): %.0f ms, %.0f ms per 100 MB%n", name,
                    file.length() >> 20, ms, per100MB);
            assertTrue(per100MB < 3000, name + ": " + per100MB + " ms per 100 MB");

            ByteStats out = new ByteStats();
            long length = file.length();
            Random random = new Random(1);
            start = System.nanoTime();
            for (int i = 0; i < 100_000; i++) {
                long from = (long) (random.nextDouble() * length);
                stats.aggregate(from, from + random.nextInt(1 << 24), out);
            }
            double perAggregate = millis(System.nanoTime() - start) / 100_000;
            System.out.printf("aggregate %s: %.4f ms%n", name, perAggregate);
            assertTrue(perAggregate < 0.1, name + ": aggregate takes " + perAggregate + " ms");
        }
    }

    @Test(groups = "performance")
    public void tileRendering() throws IOException {
        for (String name : LARGE_SAMPLES) {
            File file = sample(name);
            StructureMap map = StructureMap.of(PELoader.loadPE(file));
            ByteStatistics stats = new ByteStatistics(file);
            stats.compute(ProgressListener.NONE);
            try (CachedByteSource source = new CachedByteSource(file)) {
                FileVisualization vis = new FileVisualization(map, stats, source, RegionColorScheme.of(map));
                for (long bytesPerCell : new long[]{4096, 256, 16, 1}) {
                    ViewMapping mapping = new ViewMapping(file.length(), 0, bytesPerCell, bytesPerCell == 1 ? 16 : 64);
                    int cellWidth = bytesPerCell == 1 ? 20 : 4;
                    int cellHeight = bytesPerCell == 1 ? 14 : 4;
                    long rows = mapping.getRowCount();
                    Random random = new Random(3);
                    for (Track track : Track.values()) {
                        if ((track == Track.HEX || track == Track.ASCII) && bytesPerCell != 1) {
                            continue;
                        }
                        int width = mapping.getColumns() * cellWidth;
                        int[] argb = new int[width * 512 * cellHeight];
                        long total = 0;
                        int tiles = 20;
                        for (int i = 0; i < tiles + 5; i++) {
                            long firstRow = (long) (random.nextDouble() * Math.max(1, rows - 512));
                            Viewport viewport = new Viewport(mapping, firstRow, 512, cellHeight);
                            long start = System.nanoTime();
                            track.renderer().render(vis, viewport, cellWidth, RenderStyle.defaults(), argb, width);
                            if (i >= 5) total += System.nanoTime() - start; // the first tiles warm up
                        }
                        double perTile = millis(total) / tiles;
                        System.out.printf("tile %s %s bpc %d: %.2f ms%n", name, track, bytesPerCell, perTile);
                        double limit = track == Track.HEX || track == Track.ASCII || bytesPerCell < stats.getBlockSize()
                                ? 60 : 30;
                        assertTrue(perTile < limit, name + " " + track + " bpc " + bytesPerCell + ": " + perTile + " ms");
                    }
                }
            }
        }
    }

    @Test(groups = "performance")
    public void structureMapBuildAndLookup() throws IOException {
        for (String name : LARGE_SAMPLES) {
            File file = sample(name);
            StructureMap.of(PELoader.loadPE(file)); // warm up
            PEData data = PELoader.loadPE(file);
            long start = System.nanoTime();
            StructureMap map = StructureMap.of(data);
            double ms = millis(System.nanoTime() - start);
            System.out.printf("StructureMap %s: %.1f ms, %d regions%n", name, ms, map.getRegions().size());
            assertTrue(ms < 1500, name + ": building the map takes " + ms + " ms");

            long length = file.length();
            Random random = new Random(2);
            start = System.nanoTime();
            for (int i = 0; i < 100_000; i++) {
                map.regionsAt((long) (random.nextDouble() * length));
            }
            double perLookup = millis(System.nanoTime() - start) / 100_000;
            System.out.printf("regionsAt %s: %.4f ms%n", name, perLookup);
            assertTrue(perLookup < 0.1, name + ": regionsAt takes " + perLookup + " ms");
        }
    }
}
