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
package io.github.struppigel.tools.layout;

import io.github.struppigel.parser.PEData;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Maps file offsets to the structures of a file.
 * <p>
 * A structure map knows the {@link FileRegion}s of a file, e.g. headers,
 * sections, imports per DLL, resources, .NET streams and the overlay. It
 * answers which regions cover an offset or range, ordered from the most
 * specific (innermost) region to the least specific one.
 * <p>
 * Create a map with {@link #of(PEData)} or a {@link StructureMapBuilder}.
 * Building parses the PE file and must not run concurrently with other code
 * that uses the same PEData. A built map is immutable and thread-safe.
 * <p>
 * Example:
 * <pre>
 * {@code
 * StructureMap map = StructureMap.of(PELoader.loadPE(file));
 * for (FileRegion region : map.regionsAt(0x80)) {
 *     System.out.println(region.getPath() + " " + region);
 * }
 * }
 * </pre>
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class StructureMap {

    private final long fileLength;
    private final List<FileRegion> regions;
    private final List<FileRegion> roots;
    private final Map<RegionType, List<FileRegion>> byType;
    private final RegionIndex index;
    private final boolean truncated;

    StructureMap(long fileLength, List<FileRegion> regions, boolean truncated) {
        this.fileLength = fileLength;
        this.regions = Collections.unmodifiableList(new ArrayList<>(regions));
        List<FileRegion> rootList = new ArrayList<>();
        Map<RegionType, List<FileRegion>> types = new EnumMap<>(RegionType.class);
        for (FileRegion region : regions) {
            if (!region.getParent().isPresent()) {
                rootList.add(region);
            }
            List<FileRegion> list = types.get(region.getType());
            if (list == null) {
                list = new ArrayList<>();
                types.put(region.getType(), list);
            }
            list.add(region);
        }
        for (Map.Entry<RegionType, List<FileRegion>> entry : types.entrySet()) {
            entry.setValue(Collections.unmodifiableList(entry.getValue()));
        }
        this.roots = Collections.unmodifiableList(rootList);
        this.byType = types;
        this.index = new RegionIndex(this.regions);
        this.truncated = truncated;
    }

    /**
     * Builds the structure map of a PE file with the default settings, see
     * {@link StructureMapBuilder}.
     *
     * @param data the parsed PE file
     * @return the structure map
     */
    public static StructureMap of(PEData data) {
        return new StructureMapBuilder(data).build();
    }

    /**
     * Creates a map without regions, e.g. for files that are not PE files. To
     * show signature matches or custom regions of such files, use
     * {@link StructureMapBuilder#forUnparsedFile(java.io.File)}.
     *
     * @param fileLength the length of the file
     * @return a structure map without regions
     */
    public static StructureMap empty(long fileLength) {
        if (fileLength < 0) {
            throw new IllegalArgumentException("negative file length " + fileLength);
        }
        return new StructureMap(fileLength, Collections.<FileRegion>emptyList(), false);
    }

    /**
     * Returns all regions that contain the offset, from the innermost (most
     * specific) region to the outermost one.
     *
     * @param offset the file offset
     * @return the regions at the offset, empty if there are none
     */
    public List<FileRegion> regionsAt(long offset) {
        if (offset < 0 || offset >= fileLength) {
            return Collections.emptyList();
        }
        return index.regionsAt(offset);
    }

    /**
     * Returns the innermost (most specific) region at the offset.
     *
     * @param offset the file offset
     * @return the innermost region, absent if no region contains the offset
     */
    public Optional<FileRegion> innermostAt(long offset) {
        List<FileRegion> list = regionsAt(offset);
        return list.isEmpty() ? Optional.<FileRegion>empty() : Optional.of(list.get(0));
    }

    /**
     * Maps an offset that comes from a table row or tree node to a region: the
     * most specific region with a location that starts exactly at the offset.
     * Signature matches, anomalies and custom regions are only returned if no
     * structure starts there.
     *
     * @param offset the file offset
     * @return the best region starting at the offset, absent if there is none
     */
    public Optional<FileRegion> bestRegionStartingAt(long offset) {
        return Optional.ofNullable(index.bestStartingAt(offset));
    }

    /**
     * Returns all regions with a location that overlaps the range, from the
     * most specific region to the least specific one.
     *
     * @param from the start offset of the range
     * @param toExclusive the end offset of the range (exclusive)
     * @return the overlapping regions, empty if there are none
     */
    public List<FileRegion> regionsOverlapping(long from, long toExclusive) {
        return index.regionsOverlapping(from, toExclusive);
    }

    /**
     * Visits each location that overlaps the range, from the least specific
     * region to the most specific one, so that later visits paint over earlier
     * ones. The visited bounds are the bounds of the whole location and may
     * exceed the range.
     *
     * @param from the start offset of the range
     * @param toExclusive the end offset of the range (exclusive)
     * @param visitor receives the locations
     */
    public void forEachInterval(long from, long toExclusive, IntervalVisitor visitor) {
        index.forEachInterval(from, toExclusive, visitor);
    }

    /**
     * Returns the specificity rank of a region of this map. Rank 0 is the most
     * specific region. Smaller regions are more specific, then deeper ones,
     * then those whose type has the higher priority.
     *
     * @param region a region of this map
     * @return the rank of the region
     */
    public int getSpecificityRank(FileRegion region) {
        return index.rankOf(region);
    }

    /**
     * @return all regions in build order; the position is the region id
     */
    public List<FileRegion> getRegions() {
        return regions;
    }

    /**
     * @param type the region type
     * @return all regions of the type in build order
     */
    public List<FileRegion> getRegions(RegionType type) {
        List<FileRegion> list = byType.get(type);
        return list == null ? Collections.<FileRegion>emptyList() : list;
    }

    /**
     * @return the regions without parent in build order
     */
    public List<FileRegion> getRoots() {
        return roots;
    }

    /**
     * @return the length of the mapped file
     */
    public long getFileLength() {
        return fileLength;
    }

    /**
     * Returns whether regions were left out because the file has too many
     * structures. A summary region stands in for the left out regions of each
     * type.
     *
     * @return true if the region limit was reached
     */
    public boolean isTruncated() {
        return truncated;
    }

    /**
     * Returns a tree of all regions with half-open hexadecimal ranges, e.g.
     * <pre>
     * Headers [0x0,0x400)
     *   MSDOS Header [0x0,0x40)
     *   PE Signature [0x80,0x84)
     * </pre>
     * Siblings are sorted by start offset.
     *
     * @return the report
     */
    public String getReport() {
        StringBuilder b = new StringBuilder();
        b.append("file length: ").append(hex(fileLength)).append(" (").append(fileLength)
                .append(" bytes), ").append(regions.size()).append(" regions");
        if (truncated) {
            b.append(", truncated");
        }
        b.append(System.lineSeparator());
        appendTree(b, sortedByStart(roots), "");
        return b.toString();
    }

    private void appendTree(StringBuilder b, List<FileRegion> siblings, String indent) {
        for (FileRegion region : siblings) {
            b.append(indent).append(region.getName()).append(' ')
                    .append(hexRange(region.getStart(), region.getEnd()));
            int locations = region.getLocations().size();
            if (locations > 1) {
                b.append(' ').append(locations).append(" locations, ")
                        .append(hex(region.getCoveredBytes())).append(" bytes");
            }
            if (region.isDeclaredOnly()) {
                b.append(" declared");
            }
            if (region.isClipped()) {
                b.append(" clipped");
            }
            b.append(System.lineSeparator());
            appendTree(b, sortedByStart(region.getChildren()), indent + "  ");
        }
    }

    private static List<FileRegion> sortedByStart(List<FileRegion> list) {
        List<FileRegion> sorted = new ArrayList<>(list);
        Collections.sort(sorted, new Comparator<FileRegion>() {
            @Override
            public int compare(FileRegion a, FileRegion b) {
                int c = Long.compare(a.getStart(), b.getStart());
                return c != 0 ? c : Integer.compare(a.getId(), b.getId());
            }
        });
        return sorted;
    }

    static String hex(long value) {
        return "0x" + Long.toHexString(value);
    }

    /**
     * Formats a half-open range, e.g. "[0x80,0x84)".
     *
     * @param start the start offset
     * @param endExclusive the end offset (exclusive)
     * @return the formatted range
     */
    public static String hexRange(long start, long endExclusive) {
        return "[" + hex(start) + "," + hex(endExclusive) + ")";
    }
}
