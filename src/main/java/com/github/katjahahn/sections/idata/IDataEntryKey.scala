package com.github.katjahahn.sections.idata

object IDataEntryKey extends Enumeration {
  type IDataEntryKey = Value
  val NAME_RVA = Value("NAME_RVA")
  val I_LOOKUP_TABLE_RVA = Value("I_LOOKUP_TABLE_RVA")
  val TIME_DATE_STAMP = Value("TIME_DATE_STAMP") 
  val FORWARDER_CHAIN = Value("FORWARDER_CHAIN") 
  val I_ADDR_TABLE_RVA = Value("I_ADDR_TABLE_RVA")

}