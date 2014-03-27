/*******************************************************************************
 * Copyright 2014 Katja Hahn
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
