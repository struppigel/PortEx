/**
 * *****************************************************************************
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
 * ****************************************************************************
 */
package com.github.struppigel.tools

import com.github.struppigel.parser.IOUtil.NL
import com.github.struppigel.parser.sections.SectionHeaderKey._
import com.github.struppigel.parser.coffheader.{COFFFileHeader, COFFHeaderKey}
import com.github.struppigel.parser.{ByteArrayUtil, PEData, PELoader, StandardField}
import com.github.struppigel.parser.msdos.{MSDOSHeader, MSDOSHeaderKey}
import com.github.struppigel.parser.optheader.{DataDirEntry, OptionalHeader, OptionalHeaderKey}
import com.github.struppigel.parser.sections.{SectionCharacteristic, SectionHeader, SectionHeaderKey, SectionTable}

import java.io.File
import scala.collection.JavaConversions._
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer

/**
 * @author Karsten Hahn
 */
class DiffReportCreator(private val headers: List[PEData]) {

  /**
   * Maximum number of sections displayed in one table
   */
  val maxSec = 4

  val reportTitle = title("Diff Report") + NL +
    headers.map(_.getFile.getAbsolutePath).mkString(NL) + NL + NL

  def headerReports(): String = secTableReport + msdosHeaderReport +
    coffHeaderReport + optHeaderReport

  /**
   * Prints a report to stdout.
   */
  def printReport(): Unit = {
    print(reportTitle)
    print(headerReports)
  }

  def optHeaderReport(): String = {
    val buf = new StringBuffer()
    val colWidth = 17
    val padLength = "pointer to symbol table (deprecated) ".length

    buf.append(title("Optional Header"))

    val standardHeader = pad("standard field", padLength, " ") + pad("value", colWidth, " ") + pad("file offset", colWidth, " ")
    val windowsHeader = pad("windows field", padLength, " ") + pad("value", colWidth, " ") + pad("file offset", colWidth, " ")
    val tableLine = pad("", standardHeader.length, "-") + NL
    val optHeaders = headers.map(_.getOptionalHeader)
    val standardFields = aggregateOptionalHeaderFields(optHeaders, h => h.getStandardFields.values.toList).sortBy(_.getOffset)
    val windowsFields = aggregateOptionalHeaderFields(optHeaders, h => h.getWindowsSpecificFields.values.toList).sortBy(_.getOffset)

    for ((fields, header) <- List((standardFields, standardHeader), (windowsFields, windowsHeader))) {
      buf.append(NL + header + NL + tableLine)
      for (entry <- fields) {
        val description = entry.getDescription.replace("(reserved, must be zero)", "(reserved)").replace("(MS DOS stub, PE header, and section headers)", "")
        buf.append(pad(description, padLength, " ") + pad(hexString(entry.getValue), colWidth, " ") +
          pad(hexString(entry.getOffset), colWidth, " ") + NL)
      }
    }
    val padLengthDataDir = "delay import descriptor ".length
    val dataDirHeader = pad("data directory", padLengthDataDir, " ") + pad("rva", colWidth, " ") + pad("size", colWidth, " ") + pad("file offset", colWidth, " ")
    val dataDirs = aggregateDataDirectories(optHeaders).sortBy(_.getTableEntryOffset)
    val dataDirTableLine = pad("", dataDirHeader.length, "-") + NL
    buf.append(NL + dataDirHeader + NL + dataDirTableLine)
    for (entry <- dataDirs) {
      val description = entry.getKey.toString
      //val maybeHeader = secLoader.maybeGetSectionHeader(entry.getKey)
      val dataVA = entry.getVirtualAddress()
      //val dataOffset = new SectionLoader(data).maybeGetFileOffset(entry.getVirtualAddress())
      //val dataOffsetStr = if (dataOffset.isPresent()) hexString(dataOffset.get()) else "n.a."
      //val inSection = if (maybeHeader.isPresent) maybeHeader.get.getNumber + " " + maybeHeader.get.getName else "-"
      buf.append(pad(description, padLengthDataDir, " ") + pad(hexString(dataVA), colWidth, " ") +
        pad(hexString(entry.getDirectorySize()), colWidth, " ") +
        pad(hexString(entry.getTableEntryOffset), colWidth, " ") + NL)
    }
    buf.toString + NL
  }

  // TODO aggregate for each data dir entry
  private def aggregateDataDirectories(optHeaders: List[OptionalHeader]): List[DataDirEntry] = {
    
    def merge(m1: DataDirEntry, m2: DataDirEntry): DataDirEntry = {
      val va = if(m1.getVirtualAddress == m2.getVirtualAddress) m1.getVirtualAddress.toInt else -1
      val dirSize = if(m1.getDirectorySize == m2.getDirectorySize) m1.getDirectorySize.toInt else -1
      val offset = if(m1.getTableEntryOffset == m2.getTableEntryOffset) m1.getTableEntryOffset else -1L
      // TODO low alignment mode set to false for all
      new DataDirEntry(m1.getKey, va, dirSize, offset, false)
    }
    
    if (optHeaders.isEmpty) Nil
    else optHeaders.foldLeft(optHeaders(0).getDataDirectory.values.toList) {
      (entries, header) =>
        val commonEntries = entries.filter{ e => header.getDataDirectory.containsKey(e.getKey)}
        val result = commonEntries.map{ e => 
            val toMerge = header.getDataDirectory.get(e.getKey)
            merge(e, toMerge)    
        }
        result.toList
    }
  }

  private def aggregateOptionalHeaderFields(optHeaders: List[OptionalHeader], getFields: OptionalHeader => List[StandardField]): List[StandardField] = {
    if (optHeaders.isEmpty) Nil
    else optHeaders.foldLeft(getFields(optHeaders(0))) {
      (entries, header) =>
        entries.filter { e =>
          val eVal = e.getValue
          val hVal = header.get(e.getKey.asInstanceOf[OptionalHeaderKey])
          eVal == hVal
        }
    }
  }

  def msdosHeaderReport(): String = {
    val entries = aggregateMSDOSHeaders(headers.map(_.getMSDOSHeader)).sortBy(_.getOffset)
    val buf = new StringBuffer()
    val colWidth = 15
    val padLength = "maximum number of paragraphs allocated ".length
    buf.append(title("MSDOS Header") + NL)
    val tableHeader = pad("description", padLength, " ") + pad("value", colWidth, " ") + pad("file offset", colWidth, " ")
    buf.append(tableHeader + NL)
    buf.append(pad("", tableHeader.length, "-") + NL)
    for (key <- MSDOSHeaderKey.values) {
      val maybeEntry = entries.find(_.getKey == key)
      val value = if (maybeEntry.isDefined) hexString(maybeEntry.get.getValue) else "-"
      val offset = if (maybeEntry.isDefined) hexString(maybeEntry.get.getOffset) else "-"
      val description = headers(0).getMSDOSHeader.getField(key).getDescription
      buf.append(pad(description, padLength, " ") + pad(value, colWidth, " ") +
        pad(offset, colWidth, " ") + NL)

    }
    buf.toString + NL
  }

  def coffHeaderReport(): String = {
    val buf = new StringBuffer()
    val colWidth = 15
    val padLength = "pointer to symbol table (deprecated for image) ".length
    buf.append(title("COFF File Header") + NL)
    val tableHeader = pad("description", padLength, " ") + pad("value", colWidth, " ") + pad("file offset", colWidth, " ")
    buf.append(tableHeader + NL)
    buf.append(pad("", tableHeader.length, "-") + NL)
    val agg = aggregateCOFFHeaders(headers.map(_.getCOFFFileHeader))
    val entries = agg.sortBy(_.getOffset)
    for (key <- COFFHeaderKey.values) {
      val maybeEntry = entries.find(_.getKey == key)
      if (maybeEntry.isDefined) {
        val entry = maybeEntry.get
        val description = entry.getDescription.replace("(deprecated for image)", "(deprecated)")
        buf.append(pad(description, padLength, " ") + pad(hexString(entry.getValue), colWidth, " ") +
          pad(hexString(entry.getOffset), colWidth, " ") + NL)
      } else {
        val description = headers(0).getCOFFFileHeader.getField(key).getDescription
        buf.append(pad(description, padLength, " ") + pad("-", colWidth, " ") +
          pad("-", colWidth, " ") + NL)
      }
    }
    buf.toString + NL
  }

  private def aggregateCOFFHeaders(coffHeaders: List[COFFFileHeader]): List[StandardField] = {
    if (coffHeaders.isEmpty) Nil
    else coffHeaders.foldLeft(coffHeaders(0).getHeaderEntries.toList) {
      (entries, header) =>
        entries.filter { e =>
          val eVal = e.getValue
          val hVal = header.get(e.getKey.asInstanceOf[COFFHeaderKey])
          eVal == hVal
        }
    }
  }

  private def aggregateMSDOSHeaders(msdosHeaders: List[MSDOSHeader]): List[StandardField] = {
    if (msdosHeaders.isEmpty) Nil
    else msdosHeaders.foldLeft(msdosHeaders(0).getHeaderEntries.toList) {
      (entries, header) =>
        entries.filter { e =>
          val eVal = e.getValue
          val hVal = header.get(e.getKey.asInstanceOf[MSDOSHeaderKey])
          eVal == hVal
        }
    }
  }

  private def aggregateTables(tables: List[SectionTable]): List[SectionHeader] = {
    val sectionNumber = tables.minBy(_.getNumberOfSections).getNumberOfSections
    val list = ListBuffer[SectionHeader]()
    for (number <- 1 to sectionNumber) {
      val maybeSection = aggregateSections(tables.map(_.getSectionHeader(number)), number)
      if (maybeSection.isDefined) list += maybeSection.get
    }
    list.toList
  }

  // TODO aggregate to MIN/MAX instead of just equal values
  private def aggregateSections(sections: List[SectionHeader], sectionNumber: Int): Option[SectionHeader] = {
    if (sections.isEmpty) return None
    // initialize with first section
    val sectionName = sections.foldLeft(sections(0).getName) {
      (name, sec) => if (name == sec.getName) name else "-noname-"
    }

    var entries = sections(0).getEntryMap.asScala

    for (section <- sections) {
      val entriesCopy = collection.mutable.Map[SectionHeaderKey, StandardField]() ++= entries
      for ((key, field) <- entries) {
        if (field.getValue != section.get(key)) {
          entriesCopy.put(key, new StandardField(key, field.getDescription, -1L, field.getOffset, field.getSize))
        }
      }
      entries = entriesCopy
    }
    Some(new SectionHeader(entries, sectionNumber, 0, sectionName, 0))
  }

  def secTableReport(): String = {
    val tables = headers.map(_.getSectionTable)
    val build = new StringBuilder()
    val lowAlign = false // FIXME not sure what to do here with comparing files of different alignments
    build.append(title("Section Table"))
    val min = tables.minBy(_.getNumberOfSections).getNumberOfSections
    val max = tables.maxBy(_.getNumberOfSections).getNumberOfSections
    if (min == max) build.append(s"Section number: $min" + NL)
    else build.append(s"Section number: $min to $max" + NL)
    val allSections: List[SectionHeader] = aggregateTables(tables)
    for (secs <- allSections.grouped(maxSec).toList) {
      val sections = secs.toList
      val tableHeader = sectionEntryLine(sections, "", (s: SectionHeader) => s.getNumber() + ". " + filteredString(s.getName))
      val tableLine = pad("", tableHeader.length, "-") + NL
      build.append(tableHeader + tableLine)
      build.append(sectionEntryLine(sections, "Pointer To Raw Data",
        (s: SectionHeader) => hexString(s.get(POINTER_TO_RAW_DATA))))
      build.append(sectionEntryLine(sections, "-> aligned (act. start)",
        (s: SectionHeader) => if (s.get(POINTER_TO_RAW_DATA) != s.getAlignedPointerToRaw(lowAlign))
          hexString(s.getAlignedPointerToRaw(lowAlign)) else ""))
      build.append(sectionEntryLine(sections, "Size Of Raw Data",
        (s: SectionHeader) => hexString(s.get(SIZE_OF_RAW_DATA))))
      build.append(sectionEntryLine(sections, "Virtual Address",
        (s: SectionHeader) => hexString(s.get(VIRTUAL_ADDRESS))))
      build.append(sectionEntryLine(sections, "-> aligned",
        (s: SectionHeader) => if (s.get(VIRTUAL_ADDRESS) != s.getAlignedVirtualAddress(lowAlign))
          hexString(s.getAlignedVirtualAddress(lowAlign)) else ""))
      build.append(sectionEntryLine(sections, "Virtual Size",
        (s: SectionHeader) => hexString(s.get(VIRTUAL_SIZE))))
      build.append(sectionEntryLine(sections, "Pointer To Relocations",
        (s: SectionHeader) => hexString(s.get(POINTER_TO_RELOCATIONS))))
      build.append(sectionEntryLine(sections, "Number Of Relocations",
        (s: SectionHeader) => hexString(s.get(NUMBER_OF_RELOCATIONS))))
      build.append(sectionEntryLine(sections, "Pointer To Line Numbers",
        (s: SectionHeader) => hexString(s.get(POINTER_TO_LINE_NUMBERS))))
      build.append(sectionEntryLine(sections, "Number Of Line Numbers",
        (s: SectionHeader) => hexString(s.get(NUMBER_OF_LINE_NUMBERS))))

      for (ch <- SectionCharacteristic.values) {
        build.append(sectionEntryLine(sections, ch.shortName(),
          (s: SectionHeader) => {
            val (commonCh, notCommonCh) = aggregateSectionCharacteristics(tables.map(_.getSectionHeader(s.getNumber)))
            if (commonCh.contains(ch)) "x"
            else if (notCommonCh.contains(ch)) "" else "-"
          }))
      }

      build.append(NL)
    }
    build.toString
  }

  private def aggregateSectionCharacteristics(sections: List[SectionHeader]): (List[SectionCharacteristic], List[SectionCharacteristic]) = {
    if (sections.isEmpty) return (Nil, Nil)

    val commonCh = sections.foldLeft(sections(0).getCharacteristics.toList) {
      (list, sec) =>
        val ch = sec.getCharacteristics().toList
        list.filter(ch.contains)
    }
    val ch = sections(0).getCharacteristics.toList
    val invertedCh = SectionCharacteristic.values.filter(c => !ch.contains(c)).toList
    val notCommonCh = sections.foldLeft(invertedCh) {
      (list, sec) =>
        val ch = sec.getCharacteristics().toList
        list.filter(c => !ch.contains(c))
    }
    (commonCh, notCommonCh)
  }

  /*TODO The following methods are copied from ReportCreator. Use inheritance to get rid of them */

  private def sectionEntryLine(sections: List[SectionHeader], name: String, conv: SectionHeader => String): String = {
    val colWidth = 15
    val padLength = "POINTER_TO_LINE_NUMBERS  ".length
    val padding = pad(name, padLength, " ")
    val sectionValues = sections.map(s => pad(conv(s), colWidth, " ")).mkString(" ")
    if (sectionValues.trim.isEmpty()) "" else
      padding + sectionValues + NL
  }

  private def hash(array: Array[Byte]): String = ByteArrayUtil.byteToHex(array, "")

  private def title(str: String): String = str + NL + pad("", str.length, "*") + NL

  private def pad(string: String, length: Int, padStr: String): String = {
    val padding = (for (i <- string.length until length by padStr.length)
      yield padStr).mkString
    string + padding
  }

  private def hexString(value: Long): String = {
    if (value < 0L) "-"
    else "0x" + java.lang.Long.toHexString(value)
  }

  private def filteredString(string: String): String = {
    val controlCode: (Char) => Boolean = (c: Char) => (c <= 32 || c == 127)
    val extendedCode: (Char) => Boolean = (c: Char) => (c <= 32 || c > 127)
    string.filterNot(controlCode).filterNot(extendedCode)
  }
}

object DiffReportCreator {

  def apply(files: List[File]): DiffReportCreator = {
    val headers: List[PEData] = files.map { file => PELoader.loadPE(file) } toList;
    new DiffReportCreator(headers)
  }

  def newInstance(files: java.util.List[File]): DiffReportCreator =
    apply(files.asScala.toList)

}