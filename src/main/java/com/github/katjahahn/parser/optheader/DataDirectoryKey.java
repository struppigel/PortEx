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

import com.github.katjahahn.parser.HeaderKey;

/**
 * Key for the data directory table.
 * 
 * @author Katja Hahn
 *
 */
public enum DataDirectoryKey implements HeaderKey {
    /**
     * Export table 
     */
	EXPORT_TABLE("export table"), 
	/**
	 * Import table 
	 */
	IMPORT_TABLE("import table"), 
	/**
	 * Resource table
	 */
	RESOURCE_TABLE("resource table"), 
	/**
	 * Exception table
	 */
	EXCEPTION_TABLE("exception table"),
	/**
	 * Attribute certificate table
	 */
	CERTIFICATE_TABLE("certificate table"), 
	/**
	 * Base relocation table
	 */
	BASE_RELOCATION_TABLE("base relocation table"), 
	/**
	 * Debug data
	 */
	DEBUG("debug"), 
	/**
	 * Reserved, must be 0. //TODO anomaly
	 */
	ARCHITECTURE("architecture"), 
	/**
	 * The RVA of the value to be stored in the global pointer register.
	 * <p>
	 * The size member of this structure must be set to zero. //TODO anomaly
	 */
	GLOBAL_PTR("global ptr"), 
	/**
	 * Thread local storage (TLS) table.
	 */
	TLS_TABLE("TLS table"), 
	/**
	 * Load configuration table
	 */
	LOAD_CONFIG_TABLE("load config table"), 
	/**
	 * Bound import table
	 */
	BOUND_IMPORT("bound import"), 
	/**
	 * Import address table
	 */
	IAT("IAT"), 
	/**
	 * Delay import descriptor
	 */
	DELAY_IMPORT_DESCRIPTOR("delay import descriptor"), 
	/**
	 * CLR runtime header
	 */
	CLR_RUNTIME_HEADER("CLR runtime header"), 
	/**
	 * Reserved, must be 0
	 */
	RESERVED("reserved"); 
	
	private String fieldName; //TODO replace with key string in spec
	
	private DataDirectoryKey(String fieldName) {
		this.fieldName= fieldName;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return fieldName;
	}
}
