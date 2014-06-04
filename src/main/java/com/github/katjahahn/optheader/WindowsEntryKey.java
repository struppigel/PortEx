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
package com.github.katjahahn.optheader;


public enum WindowsEntryKey implements OptionalHeaderKey {

	IMAGE_BASE, SECTION_ALIGNMENT, FILE_ALIGNMENT, MAJOR_OS_VERSION, 
	MINOR_OS_VERSION, MAJOR_IMAGE_VERSION, MINOR_IMAGE_VERSION, 
	MAJOR_SUBSYSTEM_VERSION, MINOR_SUBSYSTEM_VERSION, WIN32_VERSION_VALUE, 
	SIZE_OF_IMAGE, SIZE_OF_HEADERS, CHECKSUM, SUBSYSTEM, DLL_CHARACTERISTICS, 
	SIZE_OF_STACK_RESERVE, SIZE_OF_STACK_COMMIT, SIZE_OF_HEAP_RESERVE, 
	SIZE_OF_HEAP_COMMIT, LOADER_FLAGS, NUMBER_OF_RVA_AND_SIZES;
}
