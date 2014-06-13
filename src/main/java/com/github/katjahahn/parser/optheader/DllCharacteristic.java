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
package com.github.katjahahn.parser.optheader;

import com.github.katjahahn.parser.Characteristic;

/**
 * Represents the flags for the DLL Characteristic field of the optional header.
 * 
 * @author Katja Hahn
 *
 */
public enum DllCharacteristic implements Characteristic {
	/**
	 * Reserved, must be zero. Value 0x1
	 */
	RESERVED_1(true, false),
	/**
	 * Reserved, must be zero. Value 0x2
	 */
	RESERVED_2(true, false),
	/**
	 * Reserved, must be zero. Value 0x4
	 */
	RESERVED_4(true, false),
	/**
	 * Reserved, must be zero. Value 0x8
	 */
	RESERVED_8(true, false),
	/**
	 * DLL can be relocated at load time.
	 */
	IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE,
	/**
	 * Code Integrity checks are enforced.
	 */
	IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY,
	/**
	 * Image is NX compatible.
	 */
	IMAGE_DLL_CHARACTERISTICS_NX_COMPAT,
	/**
	 * Isolation aware, but do not isolate the image.
	 */
	IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
	/**
	 * Does not use structured exception (SE) handling. No SE handler may be
	 * called in this image.
	 */
	IMAGE_DLLCHARACTERISTICS_NO_SEH,
	/**
	 * Do not bind the image.
	 */
	IMAGE_DLLCHARACTERISTICS_NO_BIND,
	/**
	 * Reserved, must be zero. Value 0x1000
	 */
	RESERVED_1000(true, false),
	/**
	 * A WDM driver.
	 */
	IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,
	/**
	 * Terminal Server aware.
	 */
	IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;

	private boolean deprecated;
	private boolean reserved;

	private DllCharacteristic() {
		this.deprecated = false;
		this.reserved = false;
	}

	private DllCharacteristic(boolean reserved, boolean deprecated) {
		this.reserved = reserved;
		this.deprecated = deprecated;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isReserved() {
		return reserved;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isDeprecated() {
		return deprecated;
	}
}
