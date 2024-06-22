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

public enum FileType implements Characteristic {
	
	VFT_APP ( "application", 1L ),
	VFT_DLL ("DLL", 2L),
	VFT_DRV ("device driver", 3L),
	VFT_FONT ("font", 4L),
	VFT_STATIC_LIB ("static-link library", 7L),
	VFT_UNKNOWN ("unknown", 0L),
	VFT_VXD ("virtual device", 5L);

	private String description;
    private long value;

    private FileType(String description, long value) {
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
