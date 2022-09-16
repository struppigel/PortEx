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

import com.github.katjahahn.parser.IOUtil.{SpecificationFormat, readArray, _}
import com.github.katjahahn.parser.StandardField
import com.github.katjahahn.parser.sections.clr.CLRTable.{KEY_INDEX, SIZE_INDEX, getDescriptionForTableFlag, getTableMetaForIndex, isKnownCLRFlag, readSpecificationFromFile}
import com.github.katjahahn.tools.ReportCreator

import scala.collection.JavaConverters._

class CLRTable (private val entries : List[CLRTableEntry],
                private val idx: Int) {

  private val name = getTableMetaForIndex(idx).name

  def getTableName(): String = name
  def getEntries(): List[CLRTableEntry] = entries

  override def toString: String = {
    ReportCreator.title(name) + NL +
    entries.mkString(NL)
  }
}

class CLRTableEntry (val idx : Int,
                     val row: Int,
                     private val entriesMap : Map[CLRTableKey, StandardField],
                     private val guidHeap : Option[GuidHeap],
                     private val stringsHeap : Option[StringsHeap]) {

  private val clrFields = convertToCLRFields(entriesMap)

  private def convertToCLRFields(convertee: Map[CLRTableKey, StandardField]): Map[CLRTableKey, CLRField] =
   convertee map { case (key, sfield) => (key, convertToCLRField(sfield, key)) }

  private def convertToCLRField(sfield : StandardField, clrKey : CLRTableKey): CLRField = {
    // find out type of CLRField using the specification in Meta and the key
    val key = sfield.getKey
    val spec = readSpecificationFromFile(idx)
    val specRow = spec.find(_(KEY_INDEX) == key.toString).get
    val fieldTypeStr = specRow(SIZE_INDEX)
    val index = sfield.getValue.toInt
    fieldTypeStr match {
      case "String" => CLRStringField(new StringIndex(index, stringsHeap), sfield)
      case "Guid" => CLRGuidField(new GuidIndex(index, guidHeap), sfield)
      case _ =>
        if(isKnownCLRFlag(clrKey)) {
          val flagDescription = getDescriptionForTableFlag(sfield.getValue, clrKey).getOrElse("")
          CLRFlagField(sfield, flagDescription) // known flag types become flag fields, so that their description is proper
        } else CLRLongField(sfield) // treat unknown flags and anything else as simple standard long fields
    }
  }

  def getCLRFields(): java.util.Map[CLRTableKey, CLRField] = clrFields.asJava

  override def toString: String = {
    "Row: " + row + NL + clrFields.values.mkString(NL) + NL
  }
}

case class CLRTableMeta(index : Int, name : String, specName : String)

object CLRTable {

  val KEY_INDEX = 0
  val DESCR_INDEX = 1
  val OFFSET_INDEX = 2
  val SIZE_INDEX = 3

  def getTableMetaForIndex(idx : Int): CLRTableMeta = tableMetas.find(_.index == idx).get

  def readSpecificationFromFile(idx : Int): List[Array[String]] = readArray(CLRTable.getSpecificationNameForIndex(idx)).asScala.toList

  def getSpecificationFormat() : SpecificationFormat = new SpecificationFormat(KEY_INDEX,DESCR_INDEX,OFFSET_INDEX,SIZE_INDEX)

  def getImplementedCLRIndices : List[Int] = tableMetas.map(_.index)

  def getSpecificationNameForIndex(idx : Int) : String = tableMetas.find(_.index == idx).get.specName

  def getTableNameForIndex(idx : Int) : String = tableMetas.find(_.index == idx).get.name

  def isKnownCLRFlag(key : CLRTableKey) : Boolean = getDescriptionForTableFlag(0L, key).isDefined

  /**
   * Returns either textual description for a flag value or None if it is not a known flag type
   * @param flag the long value of the flag entry
   * @param key the CLRTableKey for the flag, basically the flag type
   * @return textual description for the flag value
   */
  def getDescriptionForTableFlag(flag : Long, key : CLRTableKey): Option[String] =
    key match {
      case CLRTableKey.ASSEMBLY_HASHALGID => Some(flag match {
          case 0x0000 => "None"
          case 0x8003 => "Reserved (MD5)"
          case 0x8004 => "SHA1"
          case _ => "unknown HashId"
        })
      case CLRTableKey.ASSEMBLY_FLAGS => Some(flag match {
          case 0x0001 => "PublicKey"
          case 0x0100 => "Retargetable"
          case 0x4000 => "DisableJITcompileOptimizer"
          case 0x8000 => "EnableJITcompileTracking"
          case _ => "unknown Assembly flag"
        })
      case _ => None
    }

  private val tableMetas = List(
    CLRTableMeta(0x00, "Module", "moduletable"),
    CLRTableMeta(0x01, "TypeRef", "typereftable"),
    CLRTableMeta(0x02, "TypeDef", "typedeftable"),
    CLRTableMeta(0x04, "Field", "fieldtable"),
    CLRTableMeta(0x06, "Method", "methoddeftable"),
    CLRTableMeta(0x08, "Param", "paramtable"),
    CLRTableMeta(0x09, "InterfaceImpl", "interfaceimpltable"),
    CLRTableMeta(0x0A, "MemberRef","memberreftable"),
    CLRTableMeta(0x0B, "Constant", "constanttable"),
    CLRTableMeta(0x0C, "CustomAttribute", "customattributetable"),
    CLRTableMeta(0x0D, "FieldMarshal", "fieldmarshaltable"),
    CLRTableMeta(0x0E, "DeclSecurity", "declsecuritytable"),
    CLRTableMeta(0x0F, "ClassLayout", "classlayouttable"),
    CLRTableMeta(0x10, "FieldLayout", "fieldlayouttable"),
    CLRTableMeta(0x11, "StandAlongSig", "standalonesigtable"),
    CLRTableMeta(0x12, "EventMap", "eventmaptable"),
    CLRTableMeta(0x14, "Event", "eventtable"),
    CLRTableMeta(0x15, "PropertyMap", "propertymaptable"),
    CLRTableMeta(0x17, "Property", "propertytable"),
    CLRTableMeta(0x18, "MethodSemantics", "methodsemanticstable"),
    CLRTableMeta(0x19, "MethodImpl", "methodimpltable"),
    CLRTableMeta(0x1A, "ModuleRef", "modulereftable"),
    CLRTableMeta(0x1B, "TypeSpec", "typespectable"),
    CLRTableMeta(0x1C, "ImplMap", "implmaptable"),
    CLRTableMeta(0x1D, "FieldRVA", "fieldrvatable"),
    CLRTableMeta(0x20, "Assembly", "assemblytable"),
    CLRTableMeta(0x21, "AssemblyProcessor", "assemblyprocessortable"),
    CLRTableMeta(0x22, "AssemblyOS", "assemblyostable"),
    CLRTableMeta(0x23, "AssemblyRef", "assemblyreftable"),
    CLRTableMeta(0x24, "AssemblyRefProcessor", "assemblyrefprocessortable"),
    CLRTableMeta(0x25, "AssemblyRefOS", "assemblyrefostable"),
    CLRTableMeta(0x26, "File", "filetable"),
    CLRTableMeta(0x27, "ExportedType", "exportedtypetable"),
    CLRTableMeta(0x28, "ManifestResource", "manifestresourcetable"),
    CLRTableMeta(0x29, "NestedClass", "nestedclasstable"),
    CLRTableMeta(0x2A, "GenericParam", "genericparamtable"),
    CLRTableMeta(0x2B, "MethodSpec", "methodspectable"),
    CLRTableMeta(0x2C, "GenericParamConstraint", "genericparamconstrainttable")
  )


}
