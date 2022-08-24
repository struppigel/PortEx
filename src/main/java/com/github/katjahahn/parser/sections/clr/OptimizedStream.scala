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

import com.github.katjahahn.parser.{MemoryMappedPE, StandardField}
import com.github.katjahahn.parser.IOUtil._
import scala.collection.JavaConverters.mapAsScalaMapConverter
import scala.collection.immutable.ListMap

class OptimizedStream(
                       val entries : Map[OptimizedStreamKey, StandardField],
                       val tableSizes : List[Int],
                       val moduleTable : ModuleTable) {

  // TODO anomaly: bits above 0x2c are set
  private val tableIdxMap = ListMap(Map(
                              0x20 -> "Assembly",
                              0x22 -> "AssemblyOS",
                              0x21 -> "AssemblyProcessor",
                              0x23 -> "AssemblyRef",
                              0x24 -> "AssemblyRefProcessor",
                              0x25 -> "AssemblyRefOS",
                              0x0F -> "ClassLayout",
                              0x0B -> "Constant",
                              0x0C -> "CustomAttribute",
                              0x0E -> "DeclSecurity",
                              0x12 -> "EventMap",
                              0x14 -> "Event",
                              0x27 -> "ExportedType",
                              0x04 -> "Field",
                              0x10 -> "FieldLayout",
                              0x0D -> "FieldMarshal",
                              0x1D -> "FieldRVA",
                              0x26 -> "File",
                              0x2A -> "GenericParam",
                              0x2C -> "GenericParamConstraint",
                              0x1C -> "ImplMap",
                              0x09 -> "InterfaceImpl",
                              0x28 -> "ManifestResource",
                              0x0A -> "MemberRef",
                              0x06 -> "MethodDef",
                              0x19 -> "MethodImpl",
                              0x18 -> "MethodSematics",
                              0x2B -> "MethodSpec",
                              0x00 -> "Module",
                              0x1A -> "ModuleRef",
                              0x29 -> "NestedClass",
                              0x08 -> "Param",
                              0x17 -> "Property",
                              0x15 -> "PropertyMap",
                              0x11 -> "StandAloneSig",
                              0x02 -> "TypeDef",
                              0x01 -> "TypeRef",
                              0x1B -> "TypeSpec"
                            ).toSeq.sortBy(_._1):_*)

  private def getIntegerValueOfField(key : OptimizedStreamKey): Int = entries.get(key).get.getValue.toInt
  private def getLongValueOfField(key : OptimizedStreamKey): Long = entries.get(key).get.getValue
  /**
   * Heap size in bytes based on heap size bit mask
   * @return heap size of #String heap in bytes
   */
  def getStringHeapSize: Int = {
    if ((getIntegerValueOfField(OptimizedStreamKey.HEAP_SIZES) & 0x1) != 0) 4 else 2
  }

  /**
   * Heap size in bytes based on heap size bit mask
   * @return heap size of #GUID heap in bytes
   */
  def getGUIDHeapSize: Int = {
    if ((getIntegerValueOfField(OptimizedStreamKey.HEAP_SIZES) & 0x2) != 0) 4 else 2
  }

  /**
   * Heap size in bytes based on heap size bit mask
   * @return heap size of #Blob heap in bytes
   */
  def getBlobHeapSize: Int = {
    if ((getIntegerValueOfField(OptimizedStreamKey.HEAP_SIZES) & 0x4) != 0) 4 else 2
  }

  /**
   * get a list of all valid tables
   * @return list of all valid tables in the stream according to VALID bitmask
   */
  def getTableNames(): List[String] = {
    getTableIndices().sorted.map(tableIdxMap(_))
  }

  /**
   * get a list of all valid tables
   * @return list of all valid tables in the stream according to VALID bitmask
   */
  def getTableIndices(): List[Int] = {
    val bitMap = getLongValueOfField(OptimizedStreamKey.VALID)
    tableIdxMap.keys.filter(key => (bitMap & math.pow(2,key).toLong) != 0).toList.sorted
  }

  def getTableIndicesToSizesMap(): Map[Int,Int] = (getTableIndices() zip tableSizes).toMap

  def getTableNamesToSizesMap(): Map[String,Int] = (getTableNames() zip tableSizes).toMap

  def getInfo: String = "#~ Stream" + NL + (entries.values.mkString(NL))
}

object OptimizedStream {

  private val spec = "optimizedstream"
  private val format = new SpecificationFormat(0, 1, 2, 3)

  /**
   * Counts the number of bits in a bitvector
   * @param bitvector the bitmask to count the number of bits for
   * @return the number of bits that are set in a bitmask
   */
  private def nrOfSetBits(bitvector: Long): Int =
    if(bitvector == 0) 0
    else 1 + nrOfSetBits(bitvector & (bitvector - 1))

  def apply(size: Long, offset : Long, mmbytes: MemoryMappedPE, stringsHeap : Option[StringsHeap], guidHeap : Option[GuidHeap]): OptimizedStream = {
    val tempBytes = mmbytes.slice(offset, offset + size)
    val entries = readHeaderEntries(classOf[OptimizedStreamKey],
      format, spec, tempBytes, 0).asScala.toMap
    val bitvector = entries.get(OptimizedStreamKey.VALID).get.getValue
    val nrOfTables = nrOfSetBits(bitvector)
    val tableSizesOffset = offset + 24
    val tableSizes = readTableSizes(mmbytes: MemoryMappedPE, tableSizesOffset, nrOfTables)
    val moduleTable = loadModuleTable(offset, mmbytes, stringsHeap, guidHeap)
    new OptimizedStream(entries, tableSizes, moduleTable)
  }

  private def loadModuleTable(offset : Long, mmbytes: MemoryMappedPE, stringsHeap : Option[StringsHeap], guidHeap : Option[GuidHeap]): ModuleTable = {
    ModuleTable(offset, mmbytes, stringsHeap, guidHeap)
  }

  private def readTableSizes(mmbytes: MemoryMappedPE, tableSizesOffset : Long, nrOfTables: Int ): List[Int] =
      (
      for(i <- 0 until nrOfTables)
        yield mmbytes.getBytesIntValue(tableSizesOffset + (i * 4), 4)
      ).toList

}
