package com.github.katjahahn.optheader;

public enum DataDirectoryKey {
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
		return fieldName;
	}
}
