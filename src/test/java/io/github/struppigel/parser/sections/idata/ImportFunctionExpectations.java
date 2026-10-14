package io.github.struppigel.parser.sections.idata;

import io.github.struppigel.parser.PhysicalLocation;
import io.github.struppigel.parser.sections.SectionLoader;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * What the data of one import function is: its lookup table entry, the hint and name entry of a function imported by
 * name, and the slot of the function in the import address table.
 */
public final class ImportFunctionExpectations {

    private ImportFunctionExpectations() {
    }

    /**
     * @return the locations of the data of the import as "from:size" strings
     */
    public static Set<String> locations(SectionLoader loader, Import imp) {
        Set<String> result = new TreeSet<>();
        PhysicalLocation entry = imp.getLocations().get(0);
        result.add(key(entry.from(), entry.size()));
        long rva;
        if (imp instanceof NameImport) {
            NameImport named = (NameImport) imp;
            rva = named.getRVA();
            Optional<Long> name = loader.maybeGetFileOffset(named.getNameRVA());
            if (name.isPresent()) {
                // two byte hint, the name and its terminating zero
                result.add(key(name.get(), 2 + named.getName().length() + 1));
            }
        } else {
            rva = ((OrdinalImport) imp).getRVA();
        }
        long lookupRva = imp.getDirEntryValue(DirectoryEntryKey.I_LOOKUP_TABLE_RVA);
        long addressRva = imp.getDirEntryValue(DirectoryEntryKey.I_ADDR_TABLE_RVA);
        if (lookupRva != 0 && addressRva != 0 && rva >= lookupRva) {
            long slotRva = addressRva + (rva - lookupRva);
            Optional<Long> slot = loader.maybeGetFileOffset(slotRva);
            if (slotRva != rva && slot.isPresent() && slot.get() != entry.from()) {
                result.add(key(slot.get(), entry.size()));
            }
        }
        return result;
    }

    public static Set<String> keys(List<PhysicalLocation> locations) {
        Set<String> result = new TreeSet<>();
        for (PhysicalLocation location : locations) {
            result.add(key(location.from(), location.size()));
        }
        return result;
    }

    public static String key(long from, long size) {
        return from + ":" + size;
    }
}
