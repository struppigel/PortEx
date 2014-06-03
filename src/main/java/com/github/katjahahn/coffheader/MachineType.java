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

public enum MachineType {
	UNKNOWN, AM33, AMD64, ARM, ARMV7, EBC, I386, IA64, M32R, MIPS16, MIPSFPU, 
	MIPSFPU16, POWERPC, POWERPCFP, R4000, SH3, SH3DSP, SH4, SH5, THUMB, WCEMIPSV2;
	
	/**
	 * Returns the key as it is used in the specification.
	 * 
	 * @return key string as it is in the specification file.
	 */
	public String getKey() {
		return "IMAGE_FILE_MACHINE_" + this.toString();
	}

}
