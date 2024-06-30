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
package com.github.struppigel.tools.sigscanner;

import com.github.struppigel.parser.IOUtil;
import com.github.struppigel.parser.ScalaIOUtil;

public class MatchedSignature {
	
	private long address;
	private String pattern;
	private String name;
	private boolean epOnly;

    private int matchedBytes;

	public MatchedSignature(long address, String pattern, String name, boolean epOnly, int matchedBytes) {
		this.address = address;
		this.name = name;
		this.pattern = pattern;
		this.epOnly = epOnly;
        this.matchedBytes = matchedBytes;
	}

    public int getMatchedBytes() { return matchedBytes; }
    public long getAddress() {
        return address;
    }

    public String getPattern() {
        return pattern;
    }

    public String getName() {
        return name;
    }

    public boolean isEpOnly() {
        return epOnly;
    }

    @Override
    public String toString() {
       return name + " bytes matched: " + matchedBytes + " at address: " + ScalaIOUtil.hex(address) +
                IOUtil.NL + "pattern: " + pattern;
    }
}
