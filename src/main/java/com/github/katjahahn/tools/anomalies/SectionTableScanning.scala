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
import AnomalySubType._
import scala.collection.mutable.ListBuffer
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.IOUtil.{ NL }
import java.util.Arrays
import com.github.katjahahn.tools.Overlay
import com.github.katjahahn.parser.sections.SectionCharacteristic
import com.github.katjahahn.parser.optheader.WindowsEntryKey
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.SectionHeader
import com.github.katjahahn.parser.StandardField
import com.github.katjahahn.parser.sections.SectionHeaderKey
import com.github.katjahahn.parser.sections.SectionCharacteristic._

/**
 * Scans the Section Table for anomalies.
 *
 * @author Katja Hahn
 */
trait SectionTableScanning extends AnomalyScanner {

  type SectionRange = (Long, Long)

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
    anomalyList ++= checkNameCharacteristicsMatch
    anomalyList ++= sectionTableInOverlay
    super.scan ::: anomalyList.toList
  }

  private def checkNameCharacteristicsMatch(): List[Anomaly] = {

    val charSecNameMap = Map(
      ".bss" -> List(IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_READ,
        IMAGE_SCN_MEM_WRITE),
      ".cormeta" -> List(IMAGE_SCN_LNK_INFO),
      ".data" -> List(IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ,
        IMAGE_SCN_MEM_WRITE),
      ".debug" -> List(IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ,
        IMAGE_SCN_MEM_DISCARDABLE),
      ".drective" -> List(IMAGE_SCN_LNK_INFO),
      ".edata" -> List(IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ),
      ".idata" -> List(IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE),
      ".idlsym" -> List(IMAGE_SCN_LNK_INFO),
      ".pdata" -> List(IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ),
      ".rdata" -> List(IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ),
      ".reloc" -> List(IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ,
        IMAGE_SCN_MEM_DISCARDABLE),
      ".rsrc" -> List(IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ),
      ".sbss" -> List(IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_READ,
        IMAGE_SCN_MEM_WRITE),
      ".sdata" -> List(IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ,
        IMAGE_SCN_MEM_WRITE),
      ".srdata" -> List(IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ),
      ".sxdata" -> List(IMAGE_SCN_LNK_INFO),
      ".text" -> List(IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ),
      ".tls" -> List(IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ,
        IMAGE_SCN_MEM_WRITE),
      ".tls$" -> List(IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ,
        IMAGE_SCN_MEM_WRITE),
      ".vsdata" -> List(IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ,
        IMAGE_SCN_MEM_WRITE),
      ".xdata" -> List(IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ))

    val anomalyList = ListBuffer[Anomaly]()
    val headers = data.getSectionTable.getSectionHeaders.asScala
    for (header <- headers) {
      val sectionName = filteredString(header.getName)
      val characs = header.getCharacteristics.asScala.toList
      val entry = header.getField(SectionHeaderKey.CHARACTERISTICS)
      if (charSecNameMap.contains(header.getName)) {
        val mustHaveCharac = charSecNameMap(header.getName)
        //Note: Almost all files don't have IMAGE_SCN_MEM_READ activated, so 
        //this is not an indicator for anything
        val notContainedCharac = mustHaveCharac.filterNot(c => c == IMAGE_SCN_MEM_READ || characs.contains(c))
        val superfluousCharac = characs.filterNot(mustHaveCharac.contains(_))
        if (!notContainedCharac.isEmpty) {
          val description = s"Section Header ${header.getNumber()} with name ${sectionName} should (but doesn't) contain the characteristics: ${notContainedCharac.mkString(", ")}"
          anomalyList += NonDefaultAnomaly(entry, description, UNUSUAL_SEC_CHARACTERISTICS)
        }
        if (!superfluousCharac.isEmpty) {
          val description = s"Section Header ${header.getNumber()} with name ${sectionName} has unusual characteristics, that shouldn't be there: ${superfluousCharac.mkString(", ")}"
          anomalyList += NonDefaultAnomaly(entry, description, UNUSUAL_SEC_CHARACTERISTICS)
        }
      }
    }
    anomalyList.toList
  }

  private def sectionTableInOverlay(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable
    val overlay = new Overlay(data)
    if (sectionTable.getOffset >= overlay.getOffset) {
      val description = s"Section Table (offset: ${sectionTable.getOffset}) moved to Overlay"
      anomalyList += StructuralAnomaly(description, SEC_TABLE_IN_OVERLAY)
    }
    anomalyList.toList
  }

  private def physicalSectionRange(section: SectionHeader): SectionRange = {
    val loader = new SectionLoader(data)
    val start = section.getAlignedPointerToRaw()
    val end = loader.getReadSize(section) + start
    return (start, end)
  }

  /**
   * Checks the section headers for control symbols in the section names and
   * unusual names.
   *
   * @return anomaly list
   */
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
      val entry = new StandardField(SectionHeaderKey.NAME, section.getName, null);
      if (sectionName != section.getName) {
        val description = s"Section Header ${section.getNumber()} has control symbols in name: ${filteredSymbols(section.getName).mkString(", ")}"
        anomalyList += new NonDefaultAnomaly(entry, description, CTRL_SYMB_IN_SEC_NAME)
      }
      if (!usualNames.contains(section.getName)) {
        val description = s"Section name is unusual: ${sectionName}";
        anomalyList += new NonDefaultAnomaly(entry, description, UNUSUAL_SEC_NAME)
      }
    }
    anomalyList.toList
  }

  /**
   * Filters control code and extended code from the given string. Returns a
   * list of the filtered symbols.
   *
   * @param str the string to filter the symbols from
   * @return list of filtered symbols, each symbol represented as unicode code string
   */
  private def filteredSymbols(str: String): List[String] = {
    def getUnicodeValue(c: Char): String = "\\u" + Integer.toHexString(c | 0x10000).substring(1)
    val controlCode: (Char) => Boolean = (c: Char) => (c <= 32 || c == 127)
    val extendedCode: (Char) => Boolean = (c: Char) => (c <= 32 || c > 127)
    str.map(c => if (controlCode(c) || extendedCode(c)) { getUnicodeValue(c) } else c.toString).toList
  }

  /**
   * Checks if SizeOfRawData is larger than the file size permits.
   *
   * @return anomaly list
   */
  //TODO tell if VA is used instead of rawdatasize.
  private def checkTooLargeSizes(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable
    val sections = sectionTable.getSectionHeaders.asScala
    for (section <- sections) {
      val sectionName = filteredString(section.getName)
      val entry = section.getField(SectionHeaderKey.SIZE_OF_RAW_DATA)
      val value = entry.value
      val alignedPointerToRaw = section.getAlignedPointerToRaw()
      if (value + alignedPointerToRaw > data.getFile().length()) {
        val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.key} + aligned pointer to raw data is larger (${value + alignedPointerToRaw}) than permitted by file length (${data.getFile.length()})"
        anomalyList += WrongValueAnomaly(entry, description, TOO_LARGE_SIZE_OF_RAW)
      }
    }
    anomalyList.toList
  }

  /**
   * Checks extended reloc constraints.
   *
   * @return anomaly list
   */
  private def checkExtendedReloc(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable
    val sections = sectionTable.getSectionHeaders.asScala
    for (section <- sections) {
      if (section.getCharacteristics().contains(IMAGE_SCN_LNK_NRELOC_OVFL)) {
        val sectionName = filteredString(section.getName)
        val entry = section.getField(SectionHeaderKey.NUMBER_OF_RELOCATIONS)
        val value = entry.value
        if (value != 0xffff) {
          val description = s"Section Header ${section.getNumber()} with name ${sectionName}: has IMAGE_SCN_LNK_NRELOC_OVFL characteristic --> ${entry.key} must be 0xffff, but is " + value
          anomalyList += WrongValueAnomaly(entry, description, EXTENDED_RELOC_VIOLATIONS)
        }
      }
    }
    anomalyList.toList
  }

  /**
   * Checks all sections whether they are physically overlapping or even a
   * duplicate of each other.
   *
   * @return anomaly list
   */
  private def checkOverlappingSections(): List[Anomaly] = {
    def overlaps(t1: SectionRange, t2: SectionRange): Boolean =
      !(((t1._1 < t2._1) && (t1._2 <= t2._1)) || ((t2._1 < t1._1) && (t2._2 <= t1._1)))

    def isDuplicate(sec1: SectionHeader, sec2: SectionHeader): Boolean = {
      val range1 = physicalSectionRange(sec1)
      val range2 = physicalSectionRange(sec2)
      return range1 == range2
    }
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable
    val sections = sectionTable.getSectionHeaders.asScala
    val loader = new SectionLoader(data)
    for (section <- sections) {
      val sectionName = filteredString(section.getName)
      val range1 = physicalSectionRange(section)
      for (i <- section.getNumber() + 1 to sections.length) { //correct?
        val sec = sectionTable.getSectionHeader(i)
        val range2 = physicalSectionRange(sec)
        if (isDuplicate(section, sec)) {
          val description = s"Section ${section.getNumber()} with name ${sectionName} (${range1._1}/${range1._2}) is a duplicate of section ${sec.getNumber()} with name ${filteredString(sec.getName)}"
          anomalyList += StructuralAnomaly(description, DUPLICATE_SEC)
        } else if (overlaps(range2, range1)) {
          val description = s"Section ${section.getNumber()} with name ${sectionName} (${range1._1}/${range1._2}) overlaps with section ${filteredString(sec.getName)} with number ${sec.getNumber} (${range2._1}/${range2._2})"
          anomalyList += StructuralAnomaly(description, OVERLAPPING_SEC)
        }
      }
    }
    anomalyList.toList
  }

  /**
   * Checks all section for ascending virtual addresses
   *
   * @return anomaly list
   */
  private def checkAscendingVA(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable
    val sections = sectionTable.getSectionHeaders.asScala
    var prevVA = -1
    for (section <- sections) {
      val sectionName = filteredString(section.getName)
      val entry = section.getField(SectionHeaderKey.VIRTUAL_ADDRESS)
      val sectionVA = entry.value
      if (sectionVA <= prevVA) {
        val description = s"Section Header ${section.getNumber()} with name ${sectionName}: VIRTUAL_ADDRESS (${sectionVA}) should be greater than of the previous entry (${prevVA})"
        anomalyList += WrongValueAnomaly(entry, description, NOT_ASCENDING_SEC_VA)
      }
    }
    anomalyList.toList
  }

  /**
   * Filters all control symbols and extended code from the given string. The
   * filtered string is returned.
   *
   * @return filtered string
   */
  private def filteredString(string: String): String = {
    val controlCode: (Char) => Boolean = (c: Char) => (c <= 32 || c == 127)
    val extendedCode: (Char) => Boolean = (c: Char) => (c <= 32 || c > 127)
    string.filterNot(controlCode).filterNot(extendedCode)
  }

  /**
   * Checks for reserved fields in the characteristics of the sections.
   *
   * @return anomaly list
   */
  private def checkReserved(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable
    val sections = sectionTable.getSectionHeaders.asScala
    for (section <- sections) {
      val characteristics = section.getCharacteristics().asScala
      val entry = section.getField(SectionHeaderKey.CHARACTERISTICS)
      val sectionName = filteredString(section.getName)
      characteristics.foreach(ch =>
        if (ch.isReserved) {
          val description = s"Section Header ${section.getNumber()} with name ${sectionName}: Reserved characteristic used: ${ch.toString}"
          anomalyList += ReservedAnomaly(entry, description, RESERVED_SEC_CHARACTERISTICS)
        })
    }
    anomalyList.toList
  }

  /**
   * Checks for the use of deprecated fields in the section headers.
   *
   * @return anomaly list
   */
  private def checkDeprecated(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable
    val sections = sectionTable.getSectionHeaders.asScala
    for (section <- sections) {
      val ptrLineNrEntry = section.getField(SectionHeaderKey.POINTER_TO_LINE_NUMBERS)
      val lineNrEntry = section.getField(SectionHeaderKey.NUMBER_OF_LINE_NUMBERS)
      val sectionName = filteredString(section.getName)
      val characteristics = section.getCharacteristics().asScala
      for (ch <- characteristics if ch.isDeprecated) {
        val entry = section.getField(SectionHeaderKey.CHARACTERISTICS)
        val description = s"Section Header ${section.getNumber()} with name ${sectionName}: Characteristic ${ch.toString} is deprecated"
        anomalyList += DeprecatedAnomaly(entry, description, DEPRECATED_SEC_CHARACTERISTICS)
      }
      for (entry <- List(ptrLineNrEntry, lineNrEntry) if entry.value != 0) {
        val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.key} is deprecated, but has value " + entry.value
        val subtype = if (entry.key == SectionHeaderKey.POINTER_TO_LINE_NUMBERS)
          DEPRECATED_PTR_OF_LINE_NR
        else DEPRECATED_NR_OF_LINE_NR
        anomalyList += DeprecatedAnomaly(entry, description, subtype)
      }
    }
    anomalyList.toList
  }

  /**
   * Checks each section for values that should be set, but are 0 nevertheless.
   *
   * @return anomaly list
   */
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

  /**
   * Checks if SizeOfRawData or VirtualSize is 0 and, if true, adds the anomaly
   * to the given list.
   *
   * @param anomalyList the list to add the anomalies to
   * @param section the section to check
   * @param sectionName the name to use for the anomaly description
   */
  private def checkZeroSizes(anomalyList: ListBuffer[Anomaly], section: SectionHeader, sectionName: String): Unit = {
    val sizeOfRaw = section.getField(SectionHeaderKey.SIZE_OF_RAW_DATA)
    val virtSize = section.getField(SectionHeaderKey.VIRTUAL_SIZE)
    for (entry <- List(sizeOfRaw, virtSize) if entry.value == 0) {
      val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.key} is ${entry.value}"
      val subtype = if (entry.key == SectionHeaderKey.VIRTUAL_SIZE)
        ZERO_VIRTUAL_SIZE
      else ZERO_SIZE_OF_RAW_DATA
      anomalyList += WrongValueAnomaly(entry, description, subtype)
    }
  }

  /**
   * Checks the constraints for the uninitialized data field in the given section.
   * Adds the anomaly to the given list if constraints are violated.
   *
   * @param anomalyList the list to add the anomalies to
   * @param section the section to check
   * @param sectionName the name to use for the anomaly description
   */
  private def checkUninitializedDataConstraints(anomalyList: ListBuffer[Anomaly], section: SectionHeader, sectionName: String): Unit = {
    def containsOnlyUnitializedData(): Boolean =
      section.getCharacteristics().contains(IMAGE_SCN_CNT_UNINITIALIZED_DATA) &&
        !section.getCharacteristics().contains(IMAGE_SCN_CNT_INITIALIZED_DATA)

    if (containsOnlyUnitializedData()) {
      val sizeEntry = section.getField(SectionHeaderKey.SIZE_OF_RAW_DATA)
      val pointerEntry = section.getField(SectionHeaderKey.POINTER_TO_RAW_DATA)
      for (entry <- List(sizeEntry, pointerEntry) if entry.value != 0) {
        val value = entry.value
        val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.key.toString} must be 0 for sections with only uninitialized data, but is: ${value}"
        anomalyList += WrongValueAnomaly(entry, description, UNINIT_DATA_CONTRAINTS_VIOLATION)
      }
    }
  }

  /**
   * Checks SizeOfRawData and PointerOfRawData of every section for file
   * alignment constraints.
   *
   * @return anomaly list
   */
  private def checkFileAlignmentConstrains(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val fileAlignment = data.getOptionalHeader().get(WindowsEntryKey.FILE_ALIGNMENT)
    val sectionTable = data.getSectionTable()
    val sections = sectionTable.getSectionHeaders().asScala
    for (section <- sections) {
      val sizeEntry = section.getField(SectionHeaderKey.SIZE_OF_RAW_DATA)
      val pointerEntry = section.getField(SectionHeaderKey.POINTER_TO_RAW_DATA)
      val sectionName = filteredString(section.getName)
      for (entry <- List(sizeEntry, pointerEntry) if entry != null && entry.value % fileAlignment != 0) {
        val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.key} (${entry.value}) must be a multiple of File Alignment (${fileAlignment})"
        val subtype = if (entry.key == SectionHeaderKey.SIZE_OF_RAW_DATA)
          NOT_FILEALIGNED_SIZE_OF_RAW
        else NOT_FILEALIGNED_PTR_TO_RAW
        anomalyList += WrongValueAnomaly(entry, description, subtype)
      }
    }
    anomalyList.toList
  }

  /**
   * Checks characteristics of the given section. Adds anomaly to the list if
   * a section has constraints only an object file is allowed to have.
   *
   * @param anomalyList the list to add the anomalies to
   * @param section the section to check
   * @param sectionName the name to use for the anomaly description
   */
  private def checkObjectOnlyCharacteristics(anomalyList: ListBuffer[Anomaly], section: SectionHeader, sectionName: String): Unit = {
    val alignmentCharacteristics = Arrays.asList(SectionCharacteristic.values).asScala.filter(k => k.toString.contains("IMAGE_SCN_ALIGN")).toList
    val objectOnly = List(IMAGE_SCN_TYPE_NO_PAD, IMAGE_SCN_LNK_INFO, IMAGE_SCN_LNK_REMOVE, IMAGE_SCN_LNK_COMDAT) ::: alignmentCharacteristics
    for (characteristic <- section.getCharacteristics().asScala if objectOnly.contains(characteristic)) {
      val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${characteristic} characteristic is only valid for object files"
      val chEntry = section.getField(SectionHeaderKey.CHARACTERISTICS)
      anomalyList += WrongValueAnomaly(chEntry, description, OBJECT_ONLY_SEC_CHARACTERISTICS)
    }
  }

  /**
   * Checks PointerTo- and NumberOfRelocations for values set. Both should be zero.
   *
   * @param anomalyList the list to add the anomalies to
   * @param section the section to check
   * @param sectionName the name to use for the anomaly description
   */
  private def checkReloc(anomalyList: ListBuffer[Anomaly], section: SectionHeader, sectionName: String): Unit = {
    val relocEntry = section.getField(SectionHeaderKey.POINTER_TO_RELOCATIONS)
    val nrRelocEntry = section.getField(SectionHeaderKey.NUMBER_OF_RELOCATIONS)
    for (entry <- List(relocEntry, nrRelocEntry) if entry.value != 0) {
      val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.key} should be 0 for images, but has value " + entry.value
      val subtype = if (entry.key == SectionHeaderKey.NUMBER_OF_RELOCATIONS)
        DEPRECATED_NR_OF_RELOC
      else DEPRECATED_PTR_TO_RELOC
      anomalyList += DeprecatedAnomaly(entry, description, subtype)
    }
  }
}
