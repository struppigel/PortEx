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
package io.github.struppigel.parser.sections.idata;

import io.github.struppigel.parser.PhysicalLocation;
import io.github.struppigel.parser.sections.SectionLoader;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Finds the data that belongs to one imported function.
 */
public final class ImportFunctionLocations {

    private ImportFunctionLocations() {
    }

    /**
     * Returns the locations of the data of an import: its lookup table entry, the hint and name entry of a function
     * imported by name, and the slot of the function in the import address table. The slot is left out if it is the
     * lookup table entry itself or can not be determined, e.g. for delay-load imports.
     *
     * @param loader the section loader of the file
     * @param imp the import
     * @return the locations, the lookup table entry first
     */
    public static List<PhysicalLocation> of(SectionLoader loader, Import imp) {
        List<PhysicalLocation> result = new ArrayList<>();
        PhysicalLocation entry = imp.getLocations().get(0);
        result.add(entry);
        long rva;
        if (imp instanceof NameImport) {
            NameImport named = (NameImport) imp;
            rva = named.getRVA();
            Optional<Long> name = loader.maybeGetFileOffset(named.getNameRVA());
            if (name.isPresent()) {
                // two byte hint, the name and its terminating zero
                result.add(new PhysicalLocation(name.get(), 2 + named.getName().length() + 1));
            }
        } else {
            rva = ((OrdinalImport) imp).getRVA();
        }
        Optional<Long> slot = addressTableSlot(loader, imp, rva);
        if (slot.isPresent() && slot.get() != entry.from()) {
            result.add(new PhysicalLocation(slot.get(), entry.size()));
        }
        return result;
    }

    /**
     * @param rva the RVA of the lookup table entry of the import
     * @return the file offset of the slot in the import address table that has the same index as the lookup table
     *         entry
     */
    private static Optional<Long> addressTableSlot(SectionLoader loader, Import imp, long rva) {
        long lookupRva;
        long addressRva;
        try {
            lookupRva = imp.getDirEntryValue(DirectoryEntryKey.I_LOOKUP_TABLE_RVA);
            addressRva = imp.getDirEntryValue(DirectoryEntryKey.I_ADDR_TABLE_RVA);
        } catch (RuntimeException e) {
            // delay-load imports have no import directory entry
            return Optional.empty();
        }
        if (lookupRva == 0 || addressRva == 0 || rva < lookupRva) {
            return Optional.empty();
        }
        long slotRva = addressRva + (rva - lookupRva);
        return slotRva == rva ? Optional.<Long>empty() : loader.maybeGetFileOffset(slotRva);
    }
}
