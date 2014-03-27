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
package com.github.katjahahn.sections.idata

//TODO implement HeaderKey

object IDataEntryKey extends Enumeration {
  type IDataEntryKey = Value
  val NAME_RVA = Value("NAME_RVA")
  val I_LOOKUP_TABLE_RVA = Value("I_LOOKUP_TABLE_RVA")
  val TIME_DATE_STAMP = Value("TIME_DATE_STAMP") 
  val FORWARDER_CHAIN = Value("FORWARDER_CHAIN") 
  val I_ADDR_TABLE_RVA = Value("I_ADDR_TABLE_RVA")

}
