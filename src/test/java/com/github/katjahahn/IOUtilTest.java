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
package com.github.katjahahn;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.testng.annotations.Test;

import com.github.katjahahn.parser.IOUtil;

public class IOUtilTest {

	@Test //TODO
	public void readArray() throws IOException {
		@SuppressWarnings("unused")
		List<String[]> spec = IOUtil.readArray("msdosheaderspec");
	}

	@Test //TODO
	public void readMap() throws IOException {
		@SuppressWarnings("unused")
		Map<String, String[]> map = IOUtil.readMap("msdosheaderspec");
	}
}
