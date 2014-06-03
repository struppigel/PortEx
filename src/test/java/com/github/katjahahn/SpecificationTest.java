package com.github.katjahahn;

import static org.testng.Assert.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import scala.actors.threadpool.Arrays;

import com.github.katjahahn.coffheader.COFFHeaderKey;
import com.github.katjahahn.coffheader.FileCharacteristic;
import com.github.katjahahn.msdos.MSDOSHeaderKey;
import com.github.katjahahn.optheader.DataDirectoryKey;
import com.github.katjahahn.optheader.DllCharacteristic;
import com.github.katjahahn.optheader.StandardFieldEntryKey;
import com.github.katjahahn.optheader.WindowsEntryKey;
import com.github.katjahahn.sections.SectionCharacteristic;
import com.github.katjahahn.sections.SectionHeaderKey;
import com.github.katjahahn.sections.debug.DebugDirTableKey;
import com.github.katjahahn.sections.edata.ExportDirTableKey;
import com.github.katjahahn.sections.idata.DirectoryTableEntryKey;
import com.github.katjahahn.sections.rsrc.ResourceDataEntryKey;
import com.github.katjahahn.sections.rsrc.ResourceDirectoryTableKey;

/**
 * Tests the specification files and their enums for coherence.
 * 
 * @author Katja Hahn
 * 
 */
public class SpecificationTest {

	private final Map<Characteristic[], String> characteristicspecs = new HashMap<>();
	private final Map<HeaderKey[], String> headerspecs = new HashMap<>();

	@BeforeClass
	public void prepare() {
		characteristicspecs.put(FileCharacteristic.values(), "characteristics");
		characteristicspecs.put(DllCharacteristic.values(),
				"dllcharacteristics");
		characteristicspecs.put(SectionCharacteristic.values(),
				"sectioncharacteristics");

		headerspecs.put(COFFHeaderKey.values(), "coffheaderspec");
		headerspecs.put(DataDirectoryKey.values(), "datadirectoriesspec");
		headerspecs.put(DebugDirTableKey.values(), "debugdirentryspec");
		headerspecs.put(ExportDirTableKey.values(), "edatadirtablespec");
		headerspecs.put(DirectoryTableEntryKey.values(), "idataentryspec");
		headerspecs.put(MSDOSHeaderKey.values(), "msdosheaderspec");
		headerspecs.put(StandardFieldEntryKey.values(),
				"optionalheaderstandardspec");
		headerspecs.put(WindowsEntryKey.values(), "optionalheaderwinspec");
		headerspecs.put(ResourceDataEntryKey.values(), "resourcedataentryspec");
		headerspecs.put(ResourceDirectoryTableKey.values(), "rsrcdirspec");
		headerspecs.put(SectionHeaderKey.values(), "sectiontablespec");
		// TODO resourcetype, machinetype
		// TODO debugtypes, subsystem
	}

	@Test
	public void characteristicCoherence() throws IOException {
		final int keyIndex = 1;
		for (Entry<Characteristic[], String> entry : characteristicspecs
				.entrySet()) {
			String specname = entry.getValue();
			Characteristic[] fields = entry.getKey();
			List<String[]> list = IOUtil.readArray(specname);
			assertEquals(list.size(), fields.length);
			for (String[] values : list) {
				String key = values[keyIndex];
				assertTrue(containsKey(Arrays.asList(fields), key));
			}
		}
	}

	@Test
	public void headerCoherence() throws IOException {
		int keyIndex = 0;
		for (Entry<HeaderKey[], String> entry : headerspecs.entrySet()) {
			String specname = entry.getValue();
			System.out.println("testing spec " + specname);
			HeaderKey[] fields = entry.getKey();
			List<String[]> list = IOUtil.readArray(specname);
			assertEquals(list.size(), fields.length);
			for (String[] values : list) {
				String key = values[keyIndex];
				assertTrue(containsKey(Arrays.asList(fields), key));
			}
		}
	}

	private <T> boolean containsKey(List<T> list, String key) {
		for (T item : list) {
			if (item.toString().equals(key)) {
				return true;
			}
		}
		return false;
	}
}
