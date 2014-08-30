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

import com.github.katjahahn.parser.PELoader
import com.github.katjahahn.parser.PEData
import java.io.File
import com.github.katjahahn.parser.IOUtil.NL
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.SectionHeaderKey._
import com.github.katjahahn.parser.sections.SectionHeader
import com.github.katjahahn.parser.sections.SectionCharacteristic
import com.github.katjahahn.tools.anomalies.PEAnomalyScanner
import com.github.katjahahn.tools.anomalies.SectionTableScanning
import com.github.katjahahn.tools.sigscanner.SignatureScanner
import com.github.katjahahn.tools.sigscanner.Jar2ExeScanner
import com.github.katjahahn.parser.coffheader.COFFHeaderKey
import com.github.katjahahn.parser.coffheader.COFFFileHeader
import com.github.katjahahn.parser.optheader.DataDirectoryKey
import com.github.katjahahn.parser.sections.debug.DebugDirectoryKey
import com.github.katjahahn.parser.ByteArrayUtil

/**
 * Utility for easy creation of PE file reports.
 *
 * @author Katja Hahn
 */
class ReportCreator(private val data: PEData) {

  /**
   * Maximum number of sections displayed in one table
   */
  val maxSec = 4

  /**
   * Prints a report to stdout.
   */
  def printReport(): Unit = {
    println(title("Report For " + data.getFile.getName))
    println("file size " + hexString(data.getFile.length))
    println("full path " + data.getFile.getAbsolutePath + NL)
    print(msdosHeaderReport)
    print(coffHeaderReport)
    print(optHeaderReport)
    print(secTableReport)
    print(importsReport)
    print(exportsReport)
    print(resourcesReport)
    print(debugReport)
    print(relocReport)
    print(overlayReport)
    print(anomalyReport)
    print(peidReport)
    print(jar2ExeReport)
    print(hashReport)
    print(maldetReport)
  }

  def hashReport(): String = {
    val hasher = new Hasher(data)
    val buf = new StringBuffer()
    buf.append(title("Hashes") + NL)
    buf.append("MD5:    " + hash(hasher.md5()) + NL)
    buf.append("SHA256: " + hash(hasher.sha256()) + NL + NL)
    val colWidth = 10
    val shaWidth = 64
    val padLength = "1. .rdata    ".length
    val tableHeader = pad("Section", padLength, " ") + pad("Type", colWidth, " ") + pad("Hash Value", shaWidth, " ")
    buf.append(tableHeader + NL)
    buf.append(pad("", tableHeader.length, "-") + NL)
    val table = data.getSectionTable
    for (number <- 1 to table.getNumberOfSections()) {
      val header = table.getSectionHeader(number)
      val secName = filteredString(header.getName)
      buf.append(pad(number + ". " + secName, padLength, " ") + pad("MD5", colWidth, " ") +
        pad(hash(hasher.md5OfSection(number)), shaWidth, " ") + NL)
      buf.append(pad("", padLength, " ") + pad("SHA256", colWidth, " ") +
        pad(hash(hasher.sha256OfSection(number)), shaWidth, " ") + NL)
    }
    buf.append(NL)
    buf.toString
  }

  private def hash(array: Array[Byte]): String = ByteArrayUtil.byteToHex(array, "")

  def debugReport(): String = {
    val loader = new SectionLoader(data)
    val maybeDebug = loader.maybeLoadDebugSection()
    if (maybeDebug.isPresent && !maybeDebug.get.isEmpty) {
      val debug = maybeDebug.get
      val buf = new StringBuffer()
      val colWidth = 17
      val padLength = "Address of Raw Data ".length
      buf.append(title("Debug Information") + NL)
      buf.append("Time Date Stamp: " + debug.getTimeDateStamp + NL)
      buf.append("Type: " + debug.getTypeDescription + NL + NL)
      val tableHeader = pad("description", padLength, " ") + pad("value", colWidth, " ") + pad("file offset", colWidth, " ")
      buf.append(tableHeader + NL)
      buf.append(pad("", tableHeader.length, "-") + NL)
      val entries = debug.getDirectoryTable.values().asScala.toList.sortBy(e => e.getOffset)
      for (entry <- entries) {
        buf.append(pad(entry.description, padLength, " ") + pad(hexString(entry.value), colWidth, " ") +
          pad(hexString(entry.getOffset), colWidth, " ") + NL)
      }
      buf.append(NL)
      buf.toString
    } else ""
  }

  def relocReport(): String = {
    val loader = new SectionLoader(data)
    val maybeReloc = loader.maybeLoadRelocSection()
    if (maybeReloc.isPresent && !maybeReloc.get.isEmpty) {
      val reloc = maybeReloc.get
      val buf = new StringBuffer()
      buf.append(title("Relocations") + NL)
      buf.append(reloc.getInfo + NL) //TODO make table
      buf.toString
    } else ""
  }

  def importsReport(): String = {
    val loader = new SectionLoader(data)
    val maybeImports = loader.maybeLoadImportSection()
    if (maybeImports.isPresent && !maybeImports.get.isEmpty) {
      val idata = maybeImports.get
      val buf = new StringBuffer()
      buf.append(title("Imports") + NL)
      val imports = idata.getImports.asScala
      for (importDll <- imports) {
        buf.append(importDll + NL)
      }
      buf.toString
    } else ""
  }

  def exportsReport(): String = {
    val loader = new SectionLoader(data)
    val maybeExports = loader.maybeLoadExportSection()
    if (maybeExports.isPresent && !maybeExports.get.isEmpty) {
      val edata = maybeExports.get
      val buf = new StringBuffer()
      buf.append(title("Exports") + NL)
      val exports = edata.getExportEntries.asScala
      for (export <- exports) {
        buf.append(export + NL)
      }
      buf.toString + NL
    } else ""
  }

  def resourcesReport(): String = {
    val loader = new SectionLoader(data)
    val maybeRSRC = loader.maybeLoadResourceSection()
    if (maybeRSRC.isPresent && !maybeRSRC.get.isEmpty) {
      val rsrc = maybeRSRC.get
      val buf = new StringBuffer()
      buf.append(title("Resources") + NL)
      val resources = rsrc.getResources.asScala
      for (resource <- resources) {
        buf.append(resource + NL)
      }
      buf.toString + NL
    } else ""
  }

  def jar2ExeReport(): String = {
    val scanner = new Jar2ExeScanner(data.getFile)
    if (scanner.scan.isEmpty()) ""
    else title("Jar to EXE Wrapper Scan") + NL + scanner.createReport + NL
  }

  def maldetReport(): String =
    title("Malware Detection Heuristic") + NL + "Malware probability: " +
      ("%3.2f" format (DetectionHeuristic.newInstance(data.getFile).malwareProbability * 100)) +
      " %" + NL + NL

  def overlayReport(): String = {
    val overlay = new Overlay(data.getFile)
    if (overlay.exists) title("Overlay") + NL + "Overlay at offset " +
      hexString(overlay.getOffset()) + NL + "Overlay size      " +
      hexString(overlay.getSize) + NL + NL
    else ""
  }

  def peidReport(): String = {
    val signatures = SignatureScanner.newInstance().scanAll(data.getFile, true)
    if (signatures.isEmpty) ""
    else title("PEID Signatures") + NL + signatures.asScala.mkString(NL) + NL + NL
  }

  def anomalyReport(): String = {
    val anomalies = PEAnomalyScanner.newInstance(data).getAnomalies.asScala
    if (anomalies.isEmpty) ""
    else title("Anomalies") + NL +
      ("* " + anomalies.map(a => a.toString).mkString(NL + "* ")) + NL + NL
  }

  def msdosHeaderReport(): String = {
    val msdos = data.getMSDOSHeader
    val entries = msdos.getHeaderEntries.asScala.sortBy(e => e.getOffset)
    val buf = new StringBuffer()
    val colWidth = 15
    val padLength = "maximum number of paragraphs allocated ".length
    buf.append(title("MSDOS Header") + NL)
    val tableHeader = pad("description", padLength, " ") + pad("value", colWidth, " ") + pad("file offset", colWidth, " ")
    buf.append(tableHeader + NL)
    buf.append(pad("", tableHeader.length, "-") + NL)
    for (entry <- entries) {
      buf.append(pad(entry.description, padLength, " ") + pad(hexString(entry.value), colWidth, " ") +
        pad(hexString(entry.getOffset), colWidth, " ") + NL)
    }
    buf.toString + NL
  }

  def coffHeaderReport(): String = {
    val coff = data.getCOFFFileHeader
    val buf = new StringBuffer()
    val colWidth = 15
    val padLength = "pointer to symbol table (deprecated) ".length
    buf.append(title("COFF File Header") + NL)
    val padLength1 = "time date stamp  ".length
    buf.append(pad("time date stamp", padLength1, " ") +
      pad(coff.getTimeDate().toLocaleString(), colWidth, " ") + NL)
    buf.append(pad("machine type", padLength1, " ") +
      pad(coff.getMachineDescription, colWidth, " ") + NL)
    buf.append(pad("characteristics", padLength1, " ") + "* " +
      coff.getCharacteristicsDescriptions().asScala.mkString(NL + pad("", padLength1, " ") + "* "))

    buf.append(NL + NL)
    val tableHeader = pad("description", padLength, " ") + pad("value", colWidth, " ") + pad("file offset", colWidth, " ")
    buf.append(tableHeader + NL)
    buf.append(pad("", tableHeader.length, "-") + NL)
    val entries = (for (key <- COFFHeaderKey.values) yield coff.getField(key)).sortBy(e => e.getOffset)
    for (entry <- entries) {
      val description = entry.description.replace("(deprecated for image)", "(deprecated)")
      buf.append(pad(description, padLength, " ") + pad(hexString(entry.value), colWidth, " ") +
        pad(hexString(entry.getOffset), colWidth, " ") + NL)
    }
    buf.toString + NL
  }

  def optHeaderReport(): String = {
    val opt = data.getOptionalHeader
    val buf = new StringBuffer()
    val colWidth = 17
    val padLength = "pointer to symbol table (deprecated) ".length
    buf.append(title("Optional Header"))
    val standardHeader = pad("standard field", padLength, " ") + pad("value", colWidth, " ") + pad("file offset", colWidth, " ")
    val windowsHeader = pad("windows field", padLength, " ") + pad("value", colWidth, " ") + pad("file offset", colWidth, " ")
    val tableLine = pad("", standardHeader.length, "-") + NL
    val standardFields = opt.getStandardFields.values.asScala.toList.sortBy(_.getOffset)
    val windowsFields = opt.getWindowsSpecificFields.values.asScala.toList.sortBy(_.getOffset)
    for ((fields, header) <- List((standardFields, standardHeader), (windowsFields, windowsHeader))) {
      buf.append(NL + header + NL + tableLine)
      for (entry <- fields) {
        val description = entry.description.replace("(reserved, must be zero)", "(reserved)").replace("(MS DOS stub, PE header, and section headers)", "")
        buf.append(pad(description, padLength, " ") + pad(hexString(entry.value), colWidth, " ") +
          pad(hexString(entry.getOffset), colWidth, " ") + NL)
      }
    }
    val padLengthDataDir = "delay import descriptor ".length
    val dataDirHeader = pad("data directory", padLengthDataDir, " ") + pad("virtual address", colWidth, " ") + pad("size", colWidth, " ") + pad("file offset", colWidth, " ")
    val dataDirs = opt.getDataDirEntries().values.asScala.toList.sortBy(e => e.getTableEntryOffset)
    buf.append(NL + dataDirHeader + NL + tableLine)
    for (entry <- dataDirs) {
      val description = entry.getKey.toString
      buf.append(pad(description, padLengthDataDir, " ") + pad(hexString(entry.getVirtualAddress()), colWidth, " ") +
        pad(hexString(entry.getDirectorySize()), colWidth, " ") + pad(hexString(entry.getTableEntryOffset), colWidth, " ") + NL)
    }
    buf.toString + NL
  }

  /**
   * Filters all control symbols and extended code from the given string. The
   * filtered string is returned.
   *
   * @return filtered string
   */
  //TODO duplicate of SectionTableScanning method
  private def filteredString(string: String): String = {
    val controlCode: (Char) => Boolean = (c: Char) => (c <= 32 || c == 127)
    val extendedCode: (Char) => Boolean = (c: Char) => (c <= 32 || c > 127)
    string.filterNot(controlCode).filterNot(extendedCode)
  }

  def secTableReport(): String = {
    val table = data.getSectionTable
    val allSections = table.getSectionHeaders.asScala
    val loader = new SectionLoader(data)
    val build = new StringBuilder();
    build.append(title("Section Table"))
    for (secs <- allSections.grouped(maxSec).toList) {
      val sections = secs.toList
      val tableHeader = sectionEntryLine(sections, "", (s: SectionHeader) => s.getNumber() + ". " + filteredString(s.getName))
      val tableLine = pad("", tableHeader.length, "-") + NL
      build.append(tableHeader + tableLine)
      val entropy = new ShannonEntropy(data)
      build.append(sectionEntryLine(sections, "Entropy", (s: SectionHeader) =>
        "%1.2f" format entropy.forSection(s.getNumber())))
      build.append(sectionEntryLine(sections, "Pointer To Raw Data",
        (s: SectionHeader) => hexString(s.get(POINTER_TO_RAW_DATA))))
      build.append(sectionEntryLine(sections, "-> aligned (act. start)",
        (s: SectionHeader) => if (s.get(POINTER_TO_RAW_DATA) != s.getAlignedPointerToRaw())
          hexString(s.getAlignedPointerToRaw) else ""))
      build.append(sectionEntryLine(sections, "Size Of Raw Data",
        (s: SectionHeader) => hexString(s.get(SIZE_OF_RAW_DATA))))
      build.append(sectionEntryLine(sections, "-> actual read size",
        (s: SectionHeader) => if (s.get(SIZE_OF_RAW_DATA) != loader.getReadSize(s))
          hexString(loader.getReadSize(s)) else ""))
      build.append(sectionEntryLine(sections, "Physical End",
        (s: SectionHeader) => hexString(loader.getReadSize(s) + s.getAlignedPointerToRaw())))
      build.append(sectionEntryLine(sections, "Virtual Address",
        (s: SectionHeader) => hexString(s.get(VIRTUAL_ADDRESS))))
      build.append(sectionEntryLine(sections, "-> aligned",
        (s: SectionHeader) => if (s.get(VIRTUAL_ADDRESS) != s.getAlignedVirtualAddress)
          hexString(s.getAlignedVirtualAddress) else ""))
      build.append(sectionEntryLine(sections, "Virtual Size",
        (s: SectionHeader) => hexString(s.get(VIRTUAL_SIZE))))
      build.append(sectionEntryLine(sections, "-> actual virtual size", (s: SectionHeader) =>
        if (s.get(VIRTUAL_SIZE) != s.getAlignedVirtualSize())
          hexString(s.getAlignedVirtualSize()) else ""))
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
          (s: SectionHeader) => if (s.getCharacteristics().contains(ch)) "x" else ""))
      }
      build.append(NL)
    }
    build.toString
  }

  private def sectionEntryLine(sections: List[SectionHeader], name: String, conv: SectionHeader => String): String = {
    val colWidth = 15
    val padLength = "POINTER_TO_LINE_NUMBERS  ".length
    val padding = pad(name, padLength, " ")
    val sectionValues = sections.map(s => pad(conv(s), colWidth, " ")).mkString(" ")
    if (sectionValues.trim.isEmpty()) "" else
      padding + sectionValues + NL
  }

  private def title(str: String): String = str + NL + pad("", str.length, "*") + NL

  private def pad(string: String, length: Int, padStr: String): String = {
    val padding = (for (i <- string.length until length by padStr.length)
      yield padStr).mkString
    string + padding
  }

  private def hexString(value: Long): String =
    "0x" + java.lang.Long.toHexString(value)
}

object ReportCreator {

  private val version = """version: 0.1
    |author: Katja Hahn
    |last update: 14.Jul 2014""".stripMargin

  private val title = "peana"

  private val usage = """Usage: java -jar peana.jar <PEfile>
    """.stripMargin

  private type OptionMap = scala.collection.mutable.Map[Symbol, String]

  def newInstance(file: File): ReportCreator =
    new ReportCreator(PELoader.loadPE(file))

  def main(args: Array[String]): Unit = {
    invokeCLI(args)
  }
  private def invokeCLI(args: Array[String]): Unit = {
    val options = nextOption(scala.collection.mutable.Map(), args.toList)
    if (args.length == 0) {
      println(usage)
    } else {
      if (options.contains('version)) {
        println(title)
        println(version)
        println()
      }
      if (options.contains('inputfile)) {
        try {
          val file = new File(options('inputfile))
          if (file.exists) {
            ReportCreator.newInstance(file).printReport
          } else {
            System.err.println("file doesn't exist");
          }
        } catch {
          case e: Exception => System.err.println("Error: " + e.getMessage);
        }
      }
    }
  }

  private def nextOption(map: OptionMap, list: List[String]): OptionMap = {
    list match {
      case Nil => map
      case "-v" :: tail =>
        nextOption(map += ('version -> ""), tail)
      case value :: Nil => nextOption(map += ('inputfile -> value), list.tail)
      case option :: tail =>
        println("Unknown option " + option + "\n" + usage)
        sys.exit(1)
    }
  }

}