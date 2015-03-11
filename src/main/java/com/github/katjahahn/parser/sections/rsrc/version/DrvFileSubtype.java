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
package com.github.katjahahn.parser.sections.rsrc.version;

public enum DrvFileSubtype implements FileSubtype {
	
	VFT2_DRV_COMM       ("communications driver", 0xAL),
	VFT2_DRV_DISPLAY    ("display driver", 0x4L),
	VFT2_DRV_INSTALLABLE("installable driver", 0x8L),
	VFT2_DRV_KEYBOARD   ("keyboard driver", 0x2L),
	VFT2_DRV_LANGUAGE   ("language driver", 0x3L),
	VFT2_DRV_MOUSE      ("mouse driver", 0x5L),
	VFT2_DRV_NETWORK    ("network driver", 0x6L),
	VFT2_DRV_PRINTER    ("printer driver", 0x1L),
	VFT2_DRV_SOUND      ("sound driver", 0x9L),
	VFT2_DRV_SYSTEM     ("system driver", 0x7L),
	VFT2_DRV_VERSIONED_PRINTER("versioned printer driver", 0xCL),
	VFT2_DRV_UNKNOWN    ("unknown driver", 0x0L);
	
	private String description;
    private long value;

    private DrvFileSubtype(String description, long value) {
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
