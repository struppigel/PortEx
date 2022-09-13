/**
 * *****************************************************************************
 * Copyright 2022 Karsten Hahn
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
 * ****************************************************************************
 */
package com.github.katjahahn.parser.sections.clr

import com.github.katjahahn.parser.IOUtil.SpecificationFormat
import com.github.katjahahn.parser.{HeaderKey, StandardField}
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.tools.ReportCreator

class CLRTable (private val entries : List[CLRTableEntry],
               private val name : String) {

  def getTableName(): String = name
  def getEntries(): List[CLRTableEntry] = entries

  override def toString: String = {
    ReportCreator.title(name) + NL +
    entries.mkString(NL)
  }
}

class CLRTableEntry (private val entries : Map[CLRTableKey, StandardField]) {

  def getEntriesMap(): Map[CLRTableKey, StandardField] = entries

  def get(key : CLRTableKey): StandardField = entries.get(key).get

  override def toString: String = {
    entries.values.mkString(NL) + NL
  }
}

case class CLRTableMeta(index : Int, name : String, specName : String)

object CLRTable {

  val KEY_INDEX = 0
  val DESCR_INDEX = 1
  val OFFSET_INDEX = 2
  val SIZE_INDEX = 3

  val tableMetas = List(
    CLRTableMeta(0x00, "Module Table", "moduletable"),
    CLRTableMeta(0x01, "TypeRef Table", "typereftable"),
    CLRTableMeta(0x02, "TypeDef Table", "typedeftable"),
    CLRTableMeta(0x04, "Field Table", "fieldtable"),
    CLRTableMeta(0x06, "Method Table", "methoddeftable")
  )

  def getSpecificationFormat() : SpecificationFormat = new SpecificationFormat(KEY_INDEX,DESCR_INDEX,OFFSET_INDEX,SIZE_INDEX)

  def getImplementedCLRIndices : List[Int] = tableMetas.map(_.index)

  def getSpecificationNameForIndex(idx : Int) : String = tableMetas.find(_.index == idx).get.specName

  def getTableNameForIndex(idx : Int) : String = tableMetas.find(_.index == idx).get.name

}
