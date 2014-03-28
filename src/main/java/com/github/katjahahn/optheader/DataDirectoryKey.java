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

import com.github.katjahahn.HeaderKey;

/**
 * Key for the data directory table.
 * 
 * @author Katja Hahn
 *
 */
public enum DataDirectoryKey implements HeaderKey {
	EXPORT_TABLE("export table"), IMPORT_TABLE("import table"), 
	RESOURCE_TABLE("resource table"), EXCEPTION_TABLE("exception table"), 
	CERTIFICATE_TABLE("certificate table"), BASE_RELOCATION_TABLE("base relocation table"), 
	DEBUG("debug"), ARCHITECTURE("architecture"), GLOBAL_PTR("global ptr"), 
	TLS_TABLE("TLS table"), LOAD_CONFIG_TABLE("load config table"), 
	BOUND_IMPORT("bound import"), IAT("IAT"), DELAY_REPORT_DESCRIPTOR("delay report descriptor"), 
	CLR_RUNTIME_HEADER("CLR runtime header"); 
	
	private String fieldName;
	
	private DataDirectoryKey(String fieldName) {
		this.fieldName= fieldName;
	}
	
	@Override
	public String toString() {
		return fieldName; //TODO why the fieldname?
	}
}
