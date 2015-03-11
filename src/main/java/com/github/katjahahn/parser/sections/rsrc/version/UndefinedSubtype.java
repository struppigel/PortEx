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

public class UndefinedSubtype implements FileSubtype {
	
	private long value;
	private boolean reserved;
	
	public UndefinedSubtype(long value) {
		this(value, false);
	}
	
	public UndefinedSubtype(long value, boolean reserved) {
		this.value = value;
		this.reserved = reserved;
	}

	@Override
	public boolean isReserved() {
		return reserved;
	}

	@Override
	public boolean isDeprecated() {
		return false;
	}

	@Override
	public String getDescription() {
		return Long.toString(value);
	}

	@Override
	public long getValue() {
		return value;
	}

}
