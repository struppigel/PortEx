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
package io.github.struppigel.parser.sections.idata;

import io.github.struppigel.parser.HeaderKey;

/**
 * Represents a key for a value of a directory table entry.
 * 
 * @author Katja Hahn
 *
 */
public enum DirectoryEntryKey implements HeaderKey {

	NAME_RVA, I_LOOKUP_TABLE_RVA, TIME_DATE_STAMP, FORWARDER_CHAIN, I_ADDR_TABLE_RVA;
}
