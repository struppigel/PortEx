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
package com.github.katjahahn.tools.anomalies

import scala.collection.mutable.ListBuffer
import com.github.katjahahn.optheader.WindowsEntryKey
import scala.collection.JavaConverters._
import com.github.katjahahn.sections.SectionHeaderKey
import com.github.katjahahn.IOUtil._
import com.github.katjahahn.sections.SectionCharacteristic._
import com.github.katjahahn.sections.SectionCharacteristic
import java.util.Arrays
import com.github.katjahahn.sections.SectionHeader
import com.github.katjahahn.StandardEntry
import com.github.katjahahn.sections.SectionLoader

/**
 * Scans the Section Table for anomalies.
 *
 * @author Katja Hahn
 */
trait SectionTableScanning extends AnomalyScanner {

  abstract override def scanReport(): String =
    "Applied Section Table Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    anomalyList ++= checkFileAlignmentConstrains
    anomalyList ++= checkZeroValues
    anomalyList ++= checkDeprecated
    anomalyList ++= checkReserved
    anomalyList ++= checkAscendingVA
    anomalyList ++= checkExtendedReloc
    anomalyList ++= checkTooLargeSizes
    anomalyList ++= checkSectionNames
    anomalyList ++= checkOverlappingSections
    super.scan ::: anomalyList.toList
  }

  private def checkSectionNames(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable
    val sections = sectionTable.getSectionHeaders.asScala
    val usualNames = List(".bss", ".cormeta", ".data", ".debug", ".drective",
      ".edata", ".idata", ".rsrc", ".idlsym", ".pdata", ".rdata", ".reloc",
      ".sbss", ".sdata", ".srdata", ".sxdata", ".text", ".tls", ".vsdata",
      ".xdata", ".debug$F", ".debug$P", ".debug$S", ".debug$T", ".tls$")
    for (section <- sections) {
      val sectionName = filteredString(section.getName)
      val entry = new StandardEntry(SectionHeaderKey.NAME, section.getName, null);
      if (sectionName != section.getName) {
        val description = s"Section Header ${section.getNumber()} has control symbols in name: ${filteredSymbols(section.getName).mkString(", ")}"
        anomalyList += new NonDefaultAnomaly(entry, description)
      }
      if (!usualNames.contains(section.getName)) {
        val description = s"Section name is unusual: ${sectionName}";
        anomalyList += new NonDefaultAnomaly(entry, description)
      }
    }
    anomalyList.toList
  }

  private def filteredSymbols(name: String): List[String] = {
    def getUnicodeValue(c: Char): String = "\\u" + Integer.toHexString(c | 0x10000).substring(1)
    val controlCode: (Char) => Boolean = (c: Char) => (c <= 32 || c == 127)
    val extendedCode: (Char) => Boolean = (c: Char) => (c <= 32 || c > 127)
    name.map(c => if (controlCode(c) || extendedCode(c)) { getUnicodeValue(c) } else c.toString).toList
  }

  private def checkTooLargeSizes(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable
    val sections = sectionTable.getSectionHeaders.asScala
    for (section <- sections) {
      val sectionName = filteredString(section.getName)
      val entry = section.getEntry(SectionHeaderKey.SIZE_OF_RAW_DATA)
      val value = entry.value
      if (value + section.getAlignedPointerToRaw() > data.getFile().length()) {
        val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.key} is larger (${value}) than permitted by file length"
        anomalyList += WrongValueAnomaly(entry, description)
      }
    }
    anomalyList.toList
  }

  private def checkExtendedReloc(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable
    val sections = sectionTable.getSectionHeaders.asScala
    for (section <- sections) {
      if (section.getCharacteristics().contains(IMAGE_SCN_LNK_NRELOC_OVFL)) {
        val sectionName = filteredString(section.getName)
        val entry = section.getEntry(SectionHeaderKey.NUMBER_OF_RELOCATIONS)
        val value = entry.value
        if (value != 0xffff) {
          val description = s"Section Header ${section.getNumber()} with name ${sectionName}: has IMAGE_SCN_LNK_NRELOC_OVFL characteristic --> ${entry.key} must be 0xffff, but is " + value
          anomalyList += WrongValueAnomaly(entry, description)
        }
      }
    }
    anomalyList.toList
  }

  private def checkOverlappingSections(): List[Anomaly] = {
    def overlaps(t1: (Long, Long), t2: (Long, Long)): Boolean = 
      !(((t1._1 < t2._1) && (t1._2 <= t2._1)) || ((t2._1 < t1._1) && (t2._2 <= t1._1)))
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable
    val sections = sectionTable.getSectionHeaders.asScala
    val loader = new SectionLoader(data)
    var prevVA = -1
    for (section <- sections) {
      val sectionName = filteredString(section.getName)
      val physStart = section.getAlignedPointerToRaw()
      val physEnd = loader.getReadSize(section) + physStart
      for (i <- section.getNumber() + 1 to sections.length) { //correct?
        val sec = sectionTable.getSectionHeader(i)
        val start = sec.getAlignedPointerToRaw()
        val end = loader.getReadSize(sec) + physStart
        if (overlaps((start, end), (physStart, physEnd))) {
          val description = s"Section Header ${section.getNumber()} with name ${sectionName} (${physStart}/${physEnd}) overlaps with section ${filteredString(sec.getName)} with number ${sec.getNumber} (${start}/${end})"
          anomalyList += StructuralAnomaly(description)
        }
      }
    }
    anomalyList.toList
  }

  private def checkAscendingVA(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable
    val sections = sectionTable.getSectionHeaders.asScala
    var prevVA = -1
    for (section <- sections) {
      val sectionName = filteredString(section.getName)
      val entry = section.getEntry(SectionHeaderKey.VIRTUAL_ADDRESS)
      val sectionVA = entry.value
      if (sectionVA <= prevVA) {
        val description = s"Section Header ${section.getNumber()} with name ${sectionName}: VIRTUAL_ADDRESS (${sectionVA}) should be greater than of the previous entry (${prevVA})"
        anomalyList += WrongValueAnomaly(entry, description)
      }
    }
    anomalyList.toList
  }

  private def filteredString(string: String): String = {
    val controlCode: (Char) => Boolean = (c: Char) => (c <= 32 || c == 127)
    val extendedCode: (Char) => Boolean = (c: Char) => (c <= 32 || c > 127)
    string.filterNot(controlCode).filterNot(extendedCode)
  }

  private def checkReserved(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable
    val sections = sectionTable.getSectionHeaders.asScala
    for (section <- sections) {
      val characteristics = section.getCharacteristics().asScala
      val entry = section.getEntry(SectionHeaderKey.CHARACTERISTICS)
      val sectionName = filteredString(section.getName)
      characteristics.foreach(ch =>
        if (ch.getDescription.contains("Reserved")) {
          val description = s"Section Header ${section.getNumber()} with name ${sectionName}: Reserved characteristic used: ${ch.toString}"
          anomalyList += ReservedAnomaly(entry, description)
        })
    }
    anomalyList.toList
  }

  private def checkDeprecated(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable
    val sections = sectionTable.getSectionHeaders.asScala
    for (section <- sections) {
      val ptrLineNrEntry = section.getEntry(SectionHeaderKey.POINTER_TO_LINE_NUMBERS)
      val lineNrEntry = section.getEntry(SectionHeaderKey.NUMBER_OF_LINE_NUMBERS)
      val sectionName = filteredString(section.getName)
      for (entry <- List(ptrLineNrEntry, lineNrEntry) if entry.value != 0) {
        val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.key} is deprecated, but has value " + entry.value
        anomalyList += DeprecatedAnomaly(entry, description)
      }
    }
    anomalyList.toList
  }

  private def checkZeroValues(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable()
    val sections = sectionTable.getSectionHeaders().asScala
    for (section <- sections) yield {
      val sectionName = filteredString(section.getName)
      checkReloc(anomalyList, section, sectionName)
      checkObjectOnlyCharacteristics(anomalyList, section, sectionName)
      checkUninitializedDataConstraints(anomalyList, section, sectionName)
      checkZeroSizes(anomalyList, section, sectionName)
    }
    anomalyList.toList
  }

  private def checkZeroSizes(anomalyList: ListBuffer[Anomaly], section: SectionHeader, sectionName: String): Unit = {
    val sizeOfRaw = section.getEntry(SectionHeaderKey.SIZE_OF_RAW_DATA)
    val virtSize = section.getEntry(SectionHeaderKey.VIRTUAL_SIZE)
    for (entry <- List(sizeOfRaw, virtSize) if entry.value == 0) {
      val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.key} is ${entry.value}"
      anomalyList += WrongValueAnomaly(entry, description)
    }
  }

  private def checkUninitializedDataConstraints(anomalyList: ListBuffer[Anomaly], section: SectionHeader, sectionName: String): Unit = {
    def containsOnlyUnitializedData(): Boolean =
      section.getCharacteristics().contains(IMAGE_SCN_CNT_UNINITIALIZED_DATA) &&
        !section.getCharacteristics().contains(IMAGE_SCN_CNT_INITIALIZED_DATA)

    if (containsOnlyUnitializedData()) {
      val sizeEntry = section.getEntry(SectionHeaderKey.SIZE_OF_RAW_DATA)
      val pointerEntry = section.getEntry(SectionHeaderKey.POINTER_TO_RAW_DATA)
      for (entry <- List(sizeEntry, pointerEntry) if entry.value != 0) {
        val value = entry.value
        val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.key.toString} must be 0 for sections with only uninitialized data, but is: ${value}"
        anomalyList += WrongValueAnomaly(entry, description)
      }
    }
  }

  private def checkFileAlignmentConstrains(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val fileAlignment = data.getOptionalHeader().get(WindowsEntryKey.FILE_ALIGNMENT)
    if (fileAlignment == null) return Nil
    val sectionTable = data.getSectionTable()
    val sections = sectionTable.getSectionHeaders().asScala
    for (section <- sections) {
      val sizeEntry = section.getEntry(SectionHeaderKey.SIZE_OF_RAW_DATA)
      val pointerEntry = section.getEntry(SectionHeaderKey.POINTER_TO_RAW_DATA)
      val sectionName = filteredString(section.getName)
      for (entry <- List(sizeEntry, pointerEntry) if entry != null && entry.value % fileAlignment != 0) {
        val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.key} (${entry.value}) must be a multiple of File Alignment (${fileAlignment})"
        anomalyList += WrongValueAnomaly(entry, description)
      }
    }
    anomalyList.toList
  }

  private def checkObjectOnlyCharacteristics(anomalyList: ListBuffer[Anomaly], section: SectionHeader, sectionName: String): Unit = {
    val alignmentCharacteristics = Arrays.asList(SectionCharacteristic.values).asScala.filter(k => k.toString.contains("IMAGE_SCN_ALIGN")).toList
    val objectOnly = List(IMAGE_SCN_TYPE_NO_PAD, IMAGE_SCN_LNK_INFO, IMAGE_SCN_LNK_REMOVE, IMAGE_SCN_LNK_COMDAT) ::: alignmentCharacteristics
    for (characteristic <- section.getCharacteristics().asScala if objectOnly.contains(characteristic)) {
      val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${characteristic} characteristic is only valid for object files"
      val chEntry = section.getEntry(SectionHeaderKey.CHARACTERISTICS)
      anomalyList += WrongValueAnomaly(chEntry, description)
    }
  }

  private def checkReloc(anomalyList: ListBuffer[Anomaly], section: SectionHeader, sectionName: String): Unit = {
    val relocEntry = section.getEntry(SectionHeaderKey.POINTER_TO_RELOCATIONS)
    val nrRelocEntry = section.getEntry(SectionHeaderKey.NUMBER_OF_RELOCATIONS)
    for (entry <- List(relocEntry, nrRelocEntry) if entry.value != 0) {
      val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.key} should be 0 for images, but has value " + entry.value
      anomalyList += DeprecatedAnomaly(entry, description)
    }
  }
}
