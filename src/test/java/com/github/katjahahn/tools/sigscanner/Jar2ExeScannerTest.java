package com.github.katjahahn.tools.sigscanner;

import static org.testng.Assert.*;

import java.io.File;
import java.util.List;

import org.testng.annotations.Test;

public class Jar2ExeScannerTest {

	@Test
	public void scanResultTest() {
		Jar2ExeScanner scanner = new Jar2ExeScanner(new File("launch4jexe.exe"));
		List<MatchedSignature> result = scanner.scan();
		for(MatchedSignature sig : result) {
			System.out.println("name: " + sig.name);
			System.out.println("address: " + sig.address);
			System.out.println("epOnly: " + sig.epOnly);
			System.out.println("signature: " + sig.signature);
			System.out.println();
		}
		assertTrue(contains(result, "[Launch4j]"));
	}
	
	private boolean contains(List<MatchedSignature> siglist, String name) {
		for(MatchedSignature sig : siglist) {
			if(sig.name.equals(name)) return true;
		}
		return false;
	}
}
