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
package com.github.struppigel.parser.sections.clr

import com.github.struppigel.parser.IOUtil._
import CLRTable._
import OptimizedStream.tableIdxMap
import com.github.struppigel.parser.{IOUtil, MemoryMappedPE, StandardField}

import java.util
import scala.collection.JavaConverters._
import scala.collection.immutable.ListMap
import scala.math.pow

class OptimizedStream(
                       val entries : Map[OptimizedStreamKey, StandardField],
                       val tableSizes : List[Int],
                       private val tables: Map[Int, CLRTable]) {

  private def getIntegerValueOfField(key : OptimizedStreamKey): Int = entries.get(key).get.getValue.toInt
  private def getLongValueOfField(key : OptimizedStreamKey): Long = entries.get(key).get.getValue

  def getCLRTable(clrTableType : CLRTableType): Option[CLRTable] = {
    tables.get(clrTableType.getIndex)
  }
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

  def getTablesInfo(): String = tables.values.mkString(NL)
}

object OptimizedStream {

  private val spec = "optimizedstream"
  private val format = new SpecificationFormat(0, 1, 2, 3)
  // size in bytes for the entry that indicates the number of rows
  private val rowNrSize = 4

  /**
   * Counts the number of bits in a bitvector
   * @param bitvector the bitmask to count the number of bits for
   * @return the number of bits that are set in a bitmask
   */
  private def nrOfSetBits(bitvector: Long): Int =
    if(bitvector == 0) 0
    else 1 + nrOfSetBits(bitvector & (bitvector - 1))

  def apply(size: Long, offset : Long, mmbytes: MemoryMappedPE, stringsHeap : Option[StringsHeap], guidHeap : Option[GuidHeap], blobHeap : Option[BlobHeap]): OptimizedStream = {
    val tempBytes = mmbytes.slice(offset, offset + size)
    val entries = readHeaderEntries(classOf[OptimizedStreamKey],
      format, spec, tempBytes, 0).asScala.toMap
    val bitvector = entries.get(OptimizedStreamKey.VALID).get.getValue
    val nrOfTables = nrOfSetBits(bitvector)
    val tableSizesOffset = offset + 24
    val tableSizes = readTableSizes(mmbytes: MemoryMappedPE, tableSizesOffset, nrOfTables)
    val moduleTableOffset = tableSizesOffset + (nrOfTables * rowNrSize)

    val tables : Map[Int, CLRTable] =
      if(!guidHeap.isDefined | !stringsHeap.isDefined | !blobHeap.isDefined ) { Map() } //do not attempt to load tables for empty heaps
      else {
        readTables(moduleTableOffset, mmbytes, stringsHeap, guidHeap, blobHeap, tableSizes, bitvector)
      }
    new OptimizedStream(entries, tableSizes, tables)
  }

  /**
   * get a list of all valid tables
   * @return list of all valid tables in the stream according to VALID bitmask
   */
  private def getValidTableIndices(bitvector : Long): List[Int] = {
    tableIdxMap.keys.filter(key => (bitvector & math.pow(2,key).toLong) != 0).toList.sorted
  }

  private def getTableIdxToSizesMap(bitvector: Long, tableSizes: List[Int]): Map[Int,Int] = (getValidTableIndices(bitvector) zip tableSizes).toMap

  private def isInt(s: String): Boolean = {
    try {
      s.toInt
      true
    } catch {
      case e: Exception => false
    }
  }

  /**
   * Convert the .NET specific specification to one that can be read by IOUtils.
   * Most important part is conversion of Index types to actual sizes and offsets. This is dependent on the sample.
   *
   * @param specification
   * @return converted specification
   */
  private def convertSpecification(specification: util.List[Array[String]], guidSize : Int, stringSize : Int, blobSize : Int, tableSizes: Map[Int, Int]) : java.util.List[Array[String]] = {

    def maxRowsInCodedTables(keyStr : String) : Long = {
      val key = CLRTableKey.valueOf(keyStr)
      val maybeTagType = TagType.getTagTypeForCLRTableKey(key)
      if(maybeTagType.isPresent) {
        val tagType = maybeTagType.get
        val tables = tagType.getAllTables
        tables.map(tbl => if(tbl != null && tableSizes.contains(tbl.getIndex)) {
          tableSizes(tbl.getIndex())
        } else 0 ).max
      } else 0 // TODO Single coded TagType?
    }

    def tagSize(keyStr : String) : Int = {
      val key = CLRTableKey.valueOf(keyStr)
      val maybeTagType = TagType.getTagTypeForCLRTableKey(key)
      if(maybeTagType.isPresent) maybeTagType.get.getSize else 0
    }

    def convertSize(sizeStr: String, keyStr : String): Int = sizeStr match {
        case "String" => stringSize
        case "Guid" => guidSize
        case "Blob" => blobSize
        // coded tokens are 2 bytes if tag and all table rows fit inside, 4 bytes otherwise
        case "Coded" => if( maxRowsInCodedTables(keyStr) < pow(2,16 - tagSize(keyStr)) ) 2 else 4
        case i : String => i.toInt // If there is an exception here, a case type is missing above
      }

    var currOffset = 0
    // converting loop
    (for (row <- specification.asScala) yield {
      val offset2convert = row(OFFSET_INDEX) // must convert
      val size2convert = row(SIZE_INDEX) //must convert
      val size = convertSize(size2convert, row(KEY_INDEX))
      // convert offset here
      if (isInt(offset2convert)) {
        currOffset = offset2convert.toInt // always overrides calculated offset
      }
      val offset = currOffset
      // update offset to the next iteration with size
      currOffset += size
      Array(row(KEY_INDEX), row(DESCR_INDEX), offset.toString, size.toString)
    }).asJava
  }

  //private def readTables(tablesOffset : Long, mmbytes: MemoryMappedPE, stringsHeap : Option[StringsHeap],
  //                       guidHeap : Option[GuidHeap], tableSizes: List[Int], bitvector: Long): Map[Int,CLRTable] = Map()


  private def readTables(tablesOffset : Long,
                         mmbytes: MemoryMappedPE,
                         stringsHeap : Option[StringsHeap],
                         guidHeap : Option[GuidHeap],
                         blobHeap : Option[BlobHeap],
                         tableSizes: List[Int],
                         bitvector: Long) : Map[Int,CLRTable] = {
    // using a standard specformat for all metadata tables
    val specFormat = CLRTable.getSpecificationFormat()
    val validIndices = getValidTableIndices(bitvector)

    var currTableOffset = tablesOffset
    // for each valid table index, if condition makes sure only already implemented tables are read
    // TODO make sure the order of the indices is correctly accessed
    val tables = for(idx <- validIndices if CLRTable.getImplementedCLRIndices.contains(idx)) yield {
      // read generic specification saved in CLRTable object
      val specification = readArray(CLRTable.getSpecificationNameForIndex(idx))
      // convert this specification by replacing the offset and size entries
      val convertedSpec = convertSpecification(specification, guidHeap.get.getIndexSize, stringsHeap.get.getIndexSize, blobHeap.get.getIndexSize, getTableIdxToSizesMap(bitvector,tableSizes))
      val rows : Int = getTableIdxToSizesMap(bitvector,tableSizes)(idx)
      // calculate the size of table entry and whole table using the specification array, row number and NIndex sizes
      val entrySize: Long = convertedSpec.asScala.last(OFFSET_INDEX).toInt + convertedSpec.asScala.last(SIZE_INDEX).toInt
      val tableSize: Long = entrySize * rows
      // determine the current table offset
      val tableStart : Long = currTableOffset
      currTableOffset += tableSize
      // for each row in tableSizes obtain new offset and read StandardFields
      val tableEntries = for(row <- 0 until rows) yield {
        val rowOffset : Long = row * entrySize // this offset is relativ to tableStart which is where headerbytes were sliced
        // obtain StandardFields via IOUtil
        // now you can read headerbytes from mmbytes
        val headerbytes = mmbytes.slice(tableStart + rowOffset, tableStart + tableSize)
        // TODO set physical offset or the phys entries will be wrong!
        val physHeaderOffset = 0
        val entries = IOUtil.readHeaderEntriesForSpec(classOf[CLRTableKey], specFormat, convertedSpec, headerbytes, physHeaderOffset)
        // this is a somewhat bad hack because I could not use generic types for headerkeys
        val cleanedupEntries = entries.asScala.toMap.filter(_._2.getDescription != "this field was not set")
        val tblentry = new CLRTableEntry(idx, row + 1, cleanedupEntries, guidHeap, stringsHeap, blobHeap)
        tblentry
      }
      val tableName = CLRTable.getTableNameForIndex(idx)
      (idx, new CLRTable(tableEntries.toList, idx))
      // yield tuple of idx and CLRTable, so you can convert to map later
    }
    tables.toMap
  }

  private def readTableSizes(mmbytes: MemoryMappedPE, tableSizesOffset : Long, nrOfTables: Int ): List[Int] = {
    (for(i <- 0 until nrOfTables)
        yield mmbytes.getBytesIntValue(tableSizesOffset + (i * rowNrSize), rowNrSize)).toList
  }

  // TODO anomaly: bits above 0x2c are set
  // TODO use CLRTable values instead, this is essentially a duplicate
  val tableIdxMap = ListMap(Map(
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
}
