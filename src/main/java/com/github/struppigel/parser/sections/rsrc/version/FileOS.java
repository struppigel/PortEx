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
package com.github.struppigel.parser.sections.rsrc.version;

import com.github.struppigel.parser.Characteristic;
import com.github.struppigel.parser.Characteristic;

public enum FileOS implements Characteristic {
	VOS_DOS      ("MS-DOS",         0x00010000L),
	VOS_NT       ("Windows NT",     0x00040000L),
	VOS_WINDOWS16("16-bit Windows", 0x00000001L),
	VOS_WINDOWS32("32-bit Windows", 0x00000004L),
	VOS_OS216    ("16-bit OS/2",    0x00020000L),
	VOS_OS232    ("32-bit OS/2",    0x00030000L),
	VOS_PM16     ("16-bit Presentation Manager",    0x00000002L),
	VOS_PM32     ("32-bit Presentation Manager",    0x00000003L),
	VOS_UNKNOWN  ("Uknown", 0L);
	
    private String description;
    private long value;

    private FileOS(String description, long value) {
        this.description = description;
        this.value = value;
    }

	@Override
	public boolean isReserved() {
		return false;
	}

	@Override
	public boolean isDeprecated() {
		return false;
	}

	@Override
	public String getDescription() {
		return description;
	}

	@Override
	public long getValue() {
		return value;
	}
    
    
}
