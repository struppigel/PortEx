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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A structure of a file and the file ranges it occupies.
 * <p>
 * The locations of a region are sorted, do not overlap and lie within the file.
 * A region can consist of several locations, e.g. the imports of a DLL are
 * spread over the descriptor, the lookup table and the hint/name entries.
 * <p>
 * Regions are created by the {@link StructureMapBuilder} and are immutable
 * once the {@link StructureMap} is built.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class FileRegion {

    /** attribute key for the number of a section */
    public static final String ATTR_SECTION_NUMBER = "Section Number";
    /** attribute key for the name of a section */
    public static final String ATTR_SECTION_NAME = "Section Name";
    /** attribute key for the characteristics of a section */
    public static final String ATTR_CHARACTERISTICS = "Characteristics";
    /** attribute key for the type of a resource, e.g. RT_ICON */
    public static final String ATTR_RESOURCE_TYPE = "Resource Type";
    /** attribute key for the name or ID of a resource */
    public static final String ATTR_RESOURCE_NAME = "Resource Name";
    /** attribute key for the language of a resource */
    public static final String ATTR_RESOURCE_LANGUAGE = "Language";
    /** attribute key for the name of an imported DLL */
    public static final String ATTR_DLL_NAME = "DLL";
    /** attribute key for the name of a .NET stream */
    public static final String ATTR_STREAM_NAME = "Stream";
    /** attribute key for the type of a debug entry */
    public static final String ATTR_DEBUG_TYPE = "Debug Type";
    /** attribute key for the data directory entry a range is declared by */
    public static final String ATTR_DATA_DIRECTORY = "Data Directory";
    /** attribute key for the type of a WIN_CERTIFICATE entry */
    public static final String ATTR_CERTIFICATE_TYPE = "Certificate Type";
    /** attribute key for the subject of a certificate */
    public static final String ATTR_CERTIFICATE_SUBJECT = "Subject";
    /** attribute key for the issuer of a certificate */
    public static final String ATTR_CERTIFICATE_ISSUER = "Issuer";
    /** attribute key for the name of a matched signature */
    public static final String ATTR_SIGNATURE_NAME = "Signature";
    /** attribute key for where a signature matched, e.g. overlay */
    public static final String ATTR_SIGNATURE_LOCATION = "Signature Location";
    /** attribute key for the key of an anomaly */
    public static final String ATTR_ANOMALY_KEY = "Anomaly Key";
    /** attribute key for the type of an anomaly */
    public static final String ATTR_ANOMALY_TYPE = "Anomaly Type";
    /** attribute key for a description, e.g. of an anomaly */
    public static final String ATTR_DESCRIPTION = "Description";
    /** attribute key for the number of regions a summary region stands for */
    public static final String ATTR_TRUNCATED = "Truncated Regions";
    /** attribute key for the value of a header field */
    public static final String ATTR_VALUE = "Value";
    /** attribute key for the name of an imported or exported function */
    public static final String ATTR_FUNCTION = "Function";
    /** attribute key for the ordinal of an exported function */
    public static final String ATTR_ORDINAL = "Ordinal";
    /** attribute key for the number of rows of a .NET metadata table */
    public static final String ATTR_ROWS = "Rows";

    private final int id;
    private final String name;
    private final RegionType type;
    private final List<PhysicalLocation> locations;
    private final long start;
    private final long end;
    private final long coveredBytes;
    private final FileRegion parent;
    private final List<FileRegion> children = new ArrayList<>();
    private final List<FileRegion> unmodifiableChildren = Collections.unmodifiableList(children);
    private final int depth;
    private final Map<String, String> attributes;
    private final boolean clipped;
    private final boolean declaredOnly;

    /**
     * Creates a region and adds it to the children of its parent.
     *
     * @param id index of the region in its structure map
     * @param name name of the region
     * @param type type of the region
     * @param locations sorted, non-overlapping, non-empty locations within the file
     * @param parent the parent region, null for a root
     * @param attributes additional information
     * @param clipped true if a location was cut to fit the file
     * @param declaredOnly true if the range is only declared, not parsed
     */
    FileRegion(int id, String name, RegionType type, List<PhysicalLocation> locations,
               FileRegion parent, Map<String, String> attributes, boolean clipped,
               boolean declaredOnly) {
        assert !locations.isEmpty();
        this.id = id;
        this.name = name;
        this.type = type;
        this.locations = Collections.unmodifiableList(new ArrayList<>(locations));
        this.start = locations.get(0).from();
        PhysicalLocation last = locations.get(locations.size() - 1);
        this.end = last.from() + last.size();
        long covered = 0;
        for (PhysicalLocation loc : locations) {
            covered += loc.size();
        }
        this.coveredBytes = covered;
        this.parent = parent;
        this.depth = parent == null ? 0 : parent.depth + 1;
        this.attributes = Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
        this.clipped = clipped;
        this.declaredOnly = declaredOnly;
        if (parent != null) {
            parent.children.add(this);
        }
    }

    /**
     * @return the index of this region in {@link StructureMap#getRegions()}
     */
    public int getId() {
        return id;
    }

    /**
     * @return the name of this region, e.g. "KERNEL32.dll" or "Section 1 (.text)"
     */
    public String getName() {
        return name;
    }

    /**
     * @return the type of this region
     */
    public RegionType getType() {
        return type;
    }

    /**
     * @return the sorted, non-overlapping file ranges of this region
     */
    public List<PhysicalLocation> getLocations() {
        return locations;
    }

    /**
     * @return the file offset of the first byte of this region
     */
    public long getStart() {
        return start;
    }

    /**
     * @return the file offset after the last byte of this region (exclusive)
     */
    public long getEnd() {
        return end;
    }

    /**
     * @return the number of bytes covered by the locations of this region
     */
    public long getCoveredBytes() {
        return coveredBytes;
    }

    /**
     * Returns whether one of the locations contains the offset.
     *
     * @param offset the file offset
     * @return true if the offset belongs to this region
     */
    public boolean contains(long offset) {
        int low = 0;
        int high = locations.size() - 1;
        while (low <= high) {
            int mid = (low + high) >>> 1;
            PhysicalLocation loc = locations.get(mid);
            if (offset < loc.from()) {
                high = mid - 1;
            } else if (offset >= loc.from() + loc.size()) {
                low = mid + 1;
            } else {
                return true;
            }
        }
        return false;
    }

    /**
     * @return the parent region, absent for roots
     */
    public Optional<FileRegion> getParent() {
        return Optional.ofNullable(parent);
    }

    /**
     * @return the child regions in build order
     */
    public List<FileRegion> getChildren() {
        return unmodifiableChildren;
    }

    /**
     * @return the number of ancestors, 0 for roots
     */
    public int getDepth() {
        return depth;
    }

    /**
     * Returns the names from the root to this region, e.g.
     * "Imports &gt; KERNEL32.dll".
     *
     * @return the path of this region
     */
    public String getPath() {
        if (parent == null) {
            return name;
        }
        return parent.getPath() + " > " + name;
    }

    /**
     * Returns additional information, e.g. the type, name and language of a
     * resource. The keys are the ATTR_* constants of this class.
     *
     * @return unmodifiable map of attributes in insertion order
     */
    public Map<String, String> getAttributes() {
        return attributes;
    }

    /**
     * @return true if a location of this region was cut because it exceeded
     *         the file
     */
    public boolean isClipped() {
        return clipped;
    }

    /**
     * Returns whether the range of this region is only declared by a data
     * directory entry. PortEx does not parse these structures, so the range
     * may be wrong for unusual files.
     *
     * @return true if the range is declared, but not parsed
     */
    public boolean isDeclaredOnly() {
        return declaredOnly;
    }

    /**
     * @return the name and the half-open range, e.g. "PE Signature [0x80,0x84)"
     */
    @Override
    public String toString() {
        return name + " " + StructureMap.hexRange(start, end);
    }
}
