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

import com.github.katjahahn.parser.Characteristic;
import com.github.katjahahn.parser.HeaderKey;
import com.github.katjahahn.parser.IOUtil;
import com.github.katjahahn.parser.coffheader.COFFHeaderKey;
import com.github.katjahahn.parser.msdos.MSDOSHeaderKey;
import com.github.katjahahn.parser.optheader.DataDirectoryKey;
import com.github.katjahahn.parser.optheader.DllCharacteristic;
import com.github.katjahahn.parser.optheader.StandardFieldEntryKey;
import com.github.katjahahn.parser.optheader.Subsystem;
import com.github.katjahahn.parser.optheader.WindowsEntryKey;
import com.github.katjahahn.parser.sections.SectionCharacteristic;
import com.github.katjahahn.parser.sections.SectionHeaderKey;
import com.github.katjahahn.parser.sections.debug.DebugDirectoryKey;
import com.github.katjahahn.parser.sections.edata.ExportDirectoryKey;
import com.github.katjahahn.parser.sections.idata.DirectoryEntryKey;
import com.github.katjahahn.parser.sections.rsrc.ResourceDataEntryKey;
import com.github.katjahahn.parser.sections.rsrc.ResourceDirectoryKey;

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
		characteristicspecs.put(DllCharacteristic.values(),
				"dllcharacteristics");
		characteristicspecs.put(SectionCharacteristic.values(),
				"sectioncharacteristics");
		characteristicspecs.put(Subsystem.values(), "subsystem");
//		characteristicspecs.put(DebugType.values(), "debugtypes"); TODO match key string to enum

		headerspecs.put(COFFHeaderKey.values(), "coffheaderspec");
		headerspecs.put(DataDirectoryKey.values(), "datadirectoriesspec");
		headerspecs.put(DebugDirectoryKey.values(), "debugdirentryspec");
		headerspecs.put(ExportDirectoryKey.values(), "edatadirtablespec");
		headerspecs.put(DirectoryEntryKey.values(), "idataentryspec");
		headerspecs.put(MSDOSHeaderKey.values(), "msdosheaderspec");
		headerspecs.put(StandardFieldEntryKey.values(),
				"optionalheaderstandardspec");
		headerspecs.put(WindowsEntryKey.values(), "optionalheaderwinspec");
		headerspecs.put(ResourceDataEntryKey.values(), "resourcedataentryspec");
		headerspecs.put(ResourceDirectoryKey.values(), "rsrcdirspec");
		headerspecs.put(SectionHeaderKey.values(), "sectiontablespec");
		// TODO resourcetype, machinetype (covered by MachineTypeTest so far), debugtypes
	}

	@SuppressWarnings("unchecked")
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

	@SuppressWarnings("unchecked")
	@Test
	public void headerCoherence() throws IOException {
		int keyIndex = 0;
		for (Entry<HeaderKey[], String> entry : headerspecs.entrySet()) {
			String specname = entry.getValue();
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
