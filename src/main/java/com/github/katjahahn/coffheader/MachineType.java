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
package com.github.katjahahn.coffheader;

import com.github.katjahahn.Characteristic;

/**
 * Represents the machine the image file can run on.
 * <p>
 * Descriptions are from the PECOFF specification.
 * 
 * @author Katja Hahn
 *
 */
public enum MachineType implements Characteristic {
	/**
	 * The contents of this field are assumed to be applicable to any machine type
	 */
	UNKNOWN,
	/**
	 * Matsushita AM33
	 */
	AM33, 
	/**
	 * x64
	 */
	AMD64, 
	/**
	 * ARM little endian
	 */
	ARM, 
	/**
	 * ARMv7 (or higher) Thumb mode only
	 */
	ARMNT, 
	/**
	 * ARMv8 in 64-bit mod
	 */
	ARM64,
	/**
	 * EFI byte code
	 */
	EBC, 
	/**
	 * Intel 386 or later processors and compatible processors
	 */
	I386, 
	/**
	 * Intel Itanium processor family
	 */
	IA64, 
	/**
	 * Mitsubishi M32R little endian
	 */
	M32R, 
	/**
	 * MIPS16
	 */
	MIPS16,
	/**
	 * MIPS with FPU
	 */
	MIPSFPU, 
	/**
	 * MIPS16 with FPU
	 */
	MIPSFPU16, 
	/**
	 * Power PC little endian
	 */
	POWERPC, 
	/**
	 * Power PC with floating point support
	 */
	POWERPCFP,
	/**
	 * MIPS little endian
	 */
	R4000, 
	/**
	 * Hitachi SH3
	 */
	SH3, 
	/**
	 * Hitachi SH3 DSP
	 */
	SH3DSP,
	/**
	 * Hitachi SH4
	 */
	SH4, 
	/**
	 * Hitachi SH5
	 */
	SH5, 
	/**
	 * ARM or Thumb ("interworking")
	 */
	THUMB, 
	/**
	 * MIPS little-endian WCE v2
	 */
	WCEMIPSV2;
	
	/**
	 * Returns the key as it is used in the specification.
	 * 
	 * @return key string as it is in the specification file.
	 */
	public String getKey() {
		return "IMAGE_FILE_MACHINE_" + this.toString();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isReserved() {
		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isDeprecated() {
		return false;
	}

}
