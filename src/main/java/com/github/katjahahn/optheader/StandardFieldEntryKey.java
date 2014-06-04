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


public enum StandardFieldEntryKey implements OptionalHeaderKey {
	MAGIC_NUMBER, MAJOR_LINKER_VERSION, MINOR_LINKER_VERSION, SIZE_OF_CODE, 
	SIZE_OF_INIT_DATA, SIZE_OF_UNINIT_DATA, ADDR_OF_ENTRY_POINT, BASE_OF_CODE, 
	BASE_OF_DATA;
}
