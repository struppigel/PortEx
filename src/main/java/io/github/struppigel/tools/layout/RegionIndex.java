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

import io.github.struppigel.parser.PhysicalLocation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Interval index over the locations of all regions of a structure map.
 * <p>
 * There is one entry per location, sorted by start offset and stored in
 * parallel arrays. A segment tree holds the maximum end offset of each node.
 * Stabbing and range queries search the entries that start before the query
 * end and only descend into nodes whose maximum end lies after the query
 * start, so they cost O(log n + k).
 * <p>
 * Each region has a specificity rank: smaller regions come first, then deeper
 * ones, then those with higher type priority. Rank 0 is the most specific
 * region.
 * <p>
 * Instances are immutable and thread-safe.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class RegionIndex {

    private final long[] starts;
    private final long[] ends;
    private final int[] entryRegion;
    /** rank of each region by region id */
    private final int[] rank;
    /** region by rank */
    private final FileRegion[] byRank;
    /** maximum end per node of the segment tree, the leaves start at index leaves */
    private final long[] maxEnd;
    private final int leaves;

    RegionIndex(List<FileRegion> regions) {
        int regionCount = regions.size();
        // specificity rank
        FileRegion[] sorted = regions.toArray(new FileRegion[0]);
        Arrays.sort(sorted, specificity(specificSizes(regions)));
        this.byRank = sorted;
        this.rank = new int[regionCount];
        for (int r = 0; r < sorted.length; r++) {
            rank[sorted[r].getId()] = r;
        }
        // entries sorted by start
        int entryCount = 0;
        for (FileRegion region : regions) {
            entryCount += region.getLocations().size();
        }
        long[][] entries = new long[entryCount][];
        int e = 0;
        for (FileRegion region : regions) {
            for (PhysicalLocation loc : region.getLocations()) {
                entries[e++] = new long[]{loc.from(), loc.from() + loc.size(), region.getId()};
            }
        }
        Arrays.sort(entries, new Comparator<long[]>() {
            @Override
            public int compare(long[] a, long[] b) {
                int c = Long.compare(a[0], b[0]);
                return c != 0 ? c : Long.compare(a[2], b[2]);
            }
        });
        this.starts = new long[entryCount];
        this.ends = new long[entryCount];
        this.entryRegion = new int[entryCount];
        for (int i = 0; i < entryCount; i++) {
            starts[i] = entries[i][0];
            ends[i] = entries[i][1];
            entryRegion[i] = (int) entries[i][2];
        }
        // segment tree of maximum ends
        int l = 1;
        while (l < Math.max(1, entryCount)) {
            l <<= 1;
        }
        this.leaves = l;
        this.maxEnd = new long[2 * l];
        Arrays.fill(maxEnd, Long.MIN_VALUE);
        System.arraycopy(ends, 0, maxEnd, l, entryCount);
        for (int node = l - 1; node >= 1; node--) {
            maxEnd[node] = Math.max(maxEnd[2 * node], maxEnd[2 * node + 1]);
        }
    }

    /**
     * Smaller regions first, then deeper ones, then higher type priority,
     * then build order. The size of a region is its covered bytes, but at
     * most one less than the size of its parent, so that a region with
     * several locations is never less specific than the region around it.
     */
    private static Comparator<FileRegion> specificity(final long[] size) {
        return new Comparator<FileRegion>() {
            @Override
            public int compare(FileRegion a, FileRegion b) {
                int c = Long.compare(size[a.getId()], size[b.getId()]);
                if (c != 0) return c;
                c = Integer.compare(b.getDepth(), a.getDepth());
                if (c != 0) return c;
                c = Integer.compare(b.getType().getPriority(), a.getType().getPriority());
                if (c != 0) return c;
                return Integer.compare(a.getId(), b.getId());
            }
        };
    }

    private static long[] specificSizes(List<FileRegion> regions) {
        long[] size = new long[regions.size()];
        boolean[] done = new boolean[regions.size()];
        for (FileRegion region : regions) {
            specificSize(region, size, done);
        }
        return size;
    }

    private static long specificSize(FileRegion region, long[] size, boolean[] done) {
        int id = region.getId();
        if (!done[id]) {
            long result = region.getCoveredBytes();
            if (region.getParent().isPresent()) {
                result = Math.min(result, specificSize(region.getParent().get(), size, done) - 1);
            }
            size[id] = result;
            done[id] = true;
        }
        return size[id];
    }

    /**
     * @param region a region of this index
     * @return the specificity rank, 0 is the most specific region
     */
    int rankOf(FileRegion region) {
        return rank[region.getId()];
    }

    /**
     * @return the number of locations in this index
     */
    int entryCount() {
        return starts.length;
    }

    /**
     * Returns all regions that contain the offset, most specific first.
     */
    List<FileRegion> regionsAt(long offset) {
        IntBuffer hits = new IntBuffer();
        collect(upperBound(offset), offset, hits);
        return regionsByRank(hits);
    }

    /**
     * Returns all regions with a location that overlaps [from, toExclusive),
     * most specific first.
     */
    List<FileRegion> regionsOverlapping(long from, long toExclusive) {
        if (toExclusive <= from) {
            return Collections.emptyList();
        }
        IntBuffer hits = new IntBuffer();
        collect(lowerBound(toExclusive), from, hits);
        return regionsByRank(hits);
    }

    /**
     * Visits each location that overlaps [from, toExclusive), from the least
     * specific region to the most specific one.
     */
    void forEachInterval(long from, long toExclusive, IntervalVisitor visitor) {
        if (toExclusive <= from) {
            return;
        }
        IntBuffer hits = new IntBuffer();
        collect(lowerBound(toExclusive), from, hits);
        int n = hits.size;
        long[] keys = new long[n];
        int maxRank = byRank.length;
        for (int i = 0; i < n; i++) {
            int entry = hits.data[i];
            // least specific region first, i.e. highest rank first
            keys[i] = ((long) (maxRank - rank[entryRegion[entry]]) << 32) | entry;
        }
        Arrays.sort(keys);
        for (long key : keys) {
            int entry = (int) key;
            visitor.visit(byRank[rank[entryRegion[entry]]], starts[entry], ends[entry]);
        }
    }

    /**
     * Returns the most specific region with a location that starts exactly at
     * the offset, or null. Signature matches, anomalies and custom regions are
     * only returned if nothing else starts there.
     */
    FileRegion bestStartingAt(long offset) {
        FileRegion best = null;
        FileRegion bestAnnotation = null;
        for (int i = lowerBound(offset); i < starts.length && starts[i] == offset; i++) {
            FileRegion region = byRank[rank[entryRegion[i]]];
            if (isAnnotation(region.getType())) {
                if (bestAnnotation == null || rankOf(region) < rankOf(bestAnnotation)) {
                    bestAnnotation = region;
                }
            } else if (best == null || rankOf(region) < rankOf(best)) {
                best = region;
            }
        }
        return best != null ? best : bestAnnotation;
    }

    private static boolean isAnnotation(RegionType type) {
        return type == RegionType.SIGNATURE_MATCH || type == RegionType.ANOMALY
                || type == RegionType.CUSTOM;
    }

    private List<FileRegion> regionsByRank(IntBuffer entries) {
        int n = entries.size;
        if (n == 0) {
            return Collections.emptyList();
        }
        int[] ranks = new int[n];
        for (int i = 0; i < n; i++) {
            ranks[i] = rank[entryRegion[entries.data[i]]];
        }
        Arrays.sort(ranks);
        List<FileRegion> result = new ArrayList<>(n);
        int previous = -1;
        for (int r : ranks) {
            if (r != previous) {
                result.add(byRank[r]);
                previous = r;
            }
        }
        return Collections.unmodifiableList(result);
    }

    /**
     * Collects the entries among the first prefixLength ones whose end is
     * greater than minEnd.
     */
    private void collect(int prefixLength, long minEnd, IntBuffer out) {
        if (prefixLength > 0) {
            collect(1, 0, leaves, prefixLength, minEnd, out);
        }
    }

    private void collect(int node, int low, int high, int prefixLength, long minEnd, IntBuffer out) {
        if (low >= prefixLength || maxEnd[node] <= minEnd) {
            return;
        }
        if (high - low == 1) {
            out.add(low);
            return;
        }
        int mid = (low + high) >>> 1;
        collect(2 * node, low, mid, prefixLength, minEnd, out);
        collect(2 * node + 1, mid, high, prefixLength, minEnd, out);
    }

    /** number of entries with start &lt;= value */
    private int upperBound(long value) {
        int low = 0;
        int high = starts.length;
        while (low < high) {
            int mid = (low + high) >>> 1;
            if (starts[mid] <= value) low = mid + 1;
            else high = mid;
        }
        return low;
    }

    /** number of entries with start &lt; value */
    private int lowerBound(long value) {
        int low = 0;
        int high = starts.length;
        while (low < high) {
            int mid = (low + high) >>> 1;
            if (starts[mid] < value) low = mid + 1;
            else high = mid;
        }
        return low;
    }

    /** growable int array */
    private static final class IntBuffer {
        int[] data = new int[16];
        int size;

        void add(int value) {
            if (size == data.length) {
                data = Arrays.copyOf(data, size * 2);
            }
            data[size++] = value;
        }
    }
}
