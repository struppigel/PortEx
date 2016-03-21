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
package com.github.katjahahn.tools

import java.io.File

import scala.PartialFunction._
import scala.collection.JavaConversions._
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.parser.IOUtil.NL
import com.github.katjahahn.parser.ByteArrayUtil
import com.github.katjahahn.parser.IOUtil
import com.github.katjahahn.parser.PEData
import com.github.katjahahn.parser.PELoader
import com.github.katjahahn.parser.ScalaIOUtil.bytes2hex
import com.github.katjahahn.parser.ScalaIOUtil.using
import com.github.katjahahn.parser.StandardField
import com.github.katjahahn.parser.sections.SectionCharacteristic
import com.github.katjahahn.parser.sections.SectionHeader
import com.github.katjahahn.parser.sections.SectionHeaderKey._
import com.github.katjahahn.parser.sections.SectionHeaderKey
import com.github.katjahahn.parser.sections.SectionTable
import com.github.katjahahn.parser.sections.rsrc.Resource

/**
 * @author katja
 */
class DiffReportCreator(private val headers: List[PEData]) {
  
  /**
   * Maximum number of sections displayed in one table
   */
  val maxSec = 4
  
  val reportTitle = title("Diff Report") + NL +
    headers.map(_.getFile.getAbsolutePath).mkString(NL) + NL + NL
    
  def headerReports(): String = secTableReport // + msdosHeaderReport +
    //coffHeaderReport + optHeaderReport

  /**
   * Prints a report to stdout.
   */
  def printReport(): Unit = {
    print(reportTitle)
    print(headerReports)
  }
  
  private def aggregateTables(tables: List[SectionTable]): List[SectionHeader] = {
    val sectionNumber = tables.minBy(_.getNumberOfSections).getNumberOfSections
    val list = ListBuffer[SectionHeader]()
    for (number <- 1 to sectionNumber) {
      list += aggregateSections(tables.map(_.getSectionHeader(number)), number)
    }
    list.toList
  }
  
  // TODO aggregate to MIN/MAX instead of just equal values
  private def aggregateSections(sections: List[SectionHeader], sectionNumber: Int): SectionHeader = {
    // initialize with first section
    var sectionName = sections(0).getName
    var entries = sections(0).getEntryMap.asScala
    
    for(section <- sections){
      if(sectionName != section.getName) {
        sectionName = "-noname-"
      }
      val entriesCopy = collection.mutable.Map[SectionHeaderKey, StandardField]() ++= entries
      for((key, field) <- entries) {
        if(field.getValue != section.get(key)){
          entriesCopy.put(key, new StandardField(key, field.getDescription, -1L, field.getOffset, field.getSize))
        }
      }
      entries = entriesCopy
    }
    new SectionHeader(entries, sectionNumber, 0, sectionName, 0)
  }
  
  def secTableReport(): String = {
    val tables = headers.map(_.getSectionTable)
    val build = new StringBuilder()
    build.append(title("Section Table"))
    val min = tables.minBy(_.getNumberOfSections).getNumberOfSections
    val max = tables.maxBy(_.getNumberOfSections).getNumberOfSections
    if(min == max) build.append(s"Section number: $min" + NL)
    else build.append(s"Section number: $min to $max" + NL)
    val allSections : List[SectionHeader] = aggregateTables(tables)
    for (secs <- allSections.grouped(maxSec).toList) {
      val sections = secs.toList
      val tableHeader = sectionEntryLine(sections, "", (s: SectionHeader) => s.getNumber() + ". " + filteredString(s.getName))
      val tableLine = pad("", tableHeader.length, "-") + NL
      build.append(tableHeader + tableLine)
      //val entropy = new ShannonEntropy(data)
      //build.append(sectionEntryLine(sections, "Entropy", (s: SectionHeader) =>
      //  "%1.2f" format (entropy.forSection(s.getNumber()) * 8)))
      build.append(sectionEntryLine(sections, "Pointer To Raw Data",
        (s: SectionHeader) => hexString(s.get(POINTER_TO_RAW_DATA))))
      build.append(sectionEntryLine(sections, "-> aligned (act. start)",
        (s: SectionHeader) => if (s.get(POINTER_TO_RAW_DATA) != s.getAlignedPointerToRaw())
          hexString(s.getAlignedPointerToRaw) else ""))
      build.append(sectionEntryLine(sections, "Size Of Raw Data",
        (s: SectionHeader) => hexString(s.get(SIZE_OF_RAW_DATA))))
      build.append(sectionEntryLine(sections, "Virtual Address",
        (s: SectionHeader) => hexString(s.get(VIRTUAL_ADDRESS))))
      build.append(sectionEntryLine(sections, "-> aligned",
        (s: SectionHeader) => if (s.get(VIRTUAL_ADDRESS) != s.getAlignedVirtualAddress)
          hexString(s.getAlignedVirtualAddress) else ""))
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
       // TODO characteristics not properly shown yet, aggregate correctly
      for (ch <- SectionCharacteristic.values) {
        build.append(sectionEntryLine(sections, ch.shortName(),
          (s: SectionHeader) => if (s.get(SectionHeaderKey.CHARACTERISTICS) < 0L) "-" 
            else if (s.getCharacteristics().contains(ch)) "x" else ""))
      }
      build.append(NL)
    }
    
    build.toString
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
    if(value < 0L) "-"
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