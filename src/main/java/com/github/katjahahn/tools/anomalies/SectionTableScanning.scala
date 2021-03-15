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

import java.util.Arrays
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer
import scala.collection.immutable.HashMap
import com.github.katjahahn.parser.Location
import com.github.katjahahn.parser.StandardField
import com.github.katjahahn.parser.sections.SectionCharacteristic
import com.github.katjahahn.parser.sections.SectionCharacteristic._
import com.github.katjahahn.parser.sections.SectionHeader
import com.github.katjahahn.parser.sections.SectionHeaderKey
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.tools.Overlay
import com.github.katjahahn.parser.IOUtil.NL
import AnomalySubType._
import com.github.katjahahn.parser.optheader.WindowsEntryKey
import com.github.katjahahn.parser.PhysicalLocation
import com.github.katjahahn.tools.ShannonEntropy

/**
 * Scans the Section Table for anomalies.
 *
 * @author Katja Hahn
 */
trait SectionTableScanning extends AnomalyScanner {
  
  private val packerNames = HashMap(
      //common
      ".arch" -> "Alpha-architecture section",
      ".bindat" -> "Binary data, e.g., by downware installers",
      ".cormeta" -> "CLR Metadata section",
      ".complua" -> "LUA compiler",
      ".fasm" -> "Flat Assembler", ".flat" -> "Flat Assembler",
      ".idlsym" -> "IDL Attributes (registered SEH)",
      ".impdata" -> "Alternative import section",
      ".orpc" -> "Code section inside rpcrt4.dll",
      ".rodata" -> "Read-only data section",
      ".script" -> "Section containing script",
      ".stab" -> "GHC (Haskell)", ".stabstr" -> "GHC (Haskell)",
      ".sxdata" -> "Registered Exception Handlers section",
      ".xdata" -> "Exception information section",
      "DGROUP" -> "Legacy data group section",
      "BSS" -> "Uninitialized Data section (Borland)",
      "CODE" -> "Code section (Borland)",
      "DATA" -> "Data section (Borland)",
      "INIT" -> "INIT section of drivers",
      "PAGE" -> "PAGE section of drivers",
      "t.Policy" -> "Trustlet section with metadata for secure kernel policy",
      //Aspack
      ".aspack" -> "Aspack packer", ".adata" -> "Aspack/Armadillo packer", 
      "ASPack" -> "Aspack packer", ".ASPack" -> "Aspack packer", 
      ".asspck" -> "Aspack packer",
      //Other
      ".ccg" -> "CCG Packer (Chinese)",
      "BitArts" -> "Crunch 2.0 Packer",
      "DAStub" -> "DAStub Dragon Armor protector",
      ".charmve" -> "Added by the PIN tool",
      // Enigma Virtual Box
      ".enigma1" -> "Enigma Virtual Box protector",
      ".enigma2" -> "Enigma Virtual Box protector",
      //Other
      "!EPack" -> "EPack packer",
      "" -> "kkrunchy packer",
      ".mackt" -> "ImpRec-created section, this file was patched/cracked",
      ".MaskPE" -> "MaskPE Packer",
      "MEW" -> "MEW packer",
      //MPRESS
      ".MPRESS1" -> "MPRESS Packer", ".MPRESS2" -> "MPRESS Packer",
      //Neolite
      ".neolite" -> "Neolite Packer", ".neolit" -> "Neolite Packer",
      //NSIS
      ".ndata" -> "Nullsoft Installer",
      //NS Pack
      ".nsp0" -> "NsPack packer",".nsp1" -> "NsPack packer",".nsp2" -> "NsPack packer",
      "nsp0" -> "NsPack packer","nsp0" -> "NsPack packer","nsp0" -> "NsPack packer",
      //Other
      ".packed" -> "RLPack Packer", //first section only
      //PEBundle
      "pebundle" -> "PEBundle Packer", "PEBundle" -> "PEBundle Packer",
      //PECompact
      "PEC2TO" -> "PECompact packer","PEC2" -> "PECompact packer",
      "pec1" -> "PECompact packer","pec2" -> "PECompact packer",
      "PEC2MO" -> "PECompact packer", "PEC2TO" -> "PECompact packer",
      "PECompact2" -> "PECompact packer",
      //Other
      "PELOCKnt" -> "PELock Protector",
      ".perplex" -> "Perplex PE-Protector",
      "PESHiELD" -> "PEShield Packer",
      ".petite" -> "Petite Packer",
      ".pinclie" -> "Added by the PIN tool",
      "ProCrypt" -> "ProCrypt Packer",
      ".RLPack" -> "RLPack Packer", //second section
      ".rmnet" -> "Ramnit virus marker",
      //RPCrypt
      "RCryptor" -> "RPCrypt Packer", ".RPCrypt" -> "RPCrypt Packer",
      //Other
      ".sforce3" -> "StarForce Protection",
      ".spack" -> "Simple Pack (by bagie)",
      ".svkp" -> "SVKP packer",
      //Themida
      ".Themida" -> "Themida","Themida" -> "Themida",
      //TSULoader
      ".tsuarch" -> "TSULoader", ".tsustub" -> "TSULoader",
      //Other
      "PEPACK!!" -> "Pepack",
      ".Upack" -> "Upack packer",
      ".ByDwing" -> "Upack packer",
      //UPX
      "UPX0" -> "UPX packer", "UPX1" -> "UPX packer", "UPX2" -> "UPX packer",
      "UPX!" -> "UPX packer", ".UPX0" -> "UPX packer", ".UPX1" -> "UPX packer",
      ".UPX2" -> "UPX packer",
      //VMProtect packer
      ".vmp0" -> "VMProtect packer",".vmp1" -> "VMProtect packer",".vmp2" -> "VMProtect packer",
      //Other
      "VProtect" -> "Vprotect Packer",
      "WinLicen" -> "WinLicense (Themida) Protector",
      ".WWPACK" -> "WWPACK Packer",
      //y0da
      ".yP" -> "Y0da Protector", ".y0da" -> "Y0da Protector"
  )

  type SectionRange = (Long, Long)

  abstract override def scanReport(): String =
    "Applied Section Table Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    anomalyList ++= checkVirtualSecTable
    anomalyList ++= checkFileAlignmentConstrains
    anomalyList ++= checkZeroValues
    anomalyList ++= checkDeprecated
    anomalyList ++= checkReserved
    anomalyList ++= checkAscendingVA
    anomalyList ++= checkExtendedReloc
    anomalyList ++= checkTooLargeSizes
    anomalyList ++= checkSectionNames
    anomalyList ++= checkOverlappingOrShuffledSections
    anomalyList ++= checkSectionCharacteristics
    anomalyList ++= sectionTableInOverlay
    super.scan ::: anomalyList.toList
  }

  private def checkVirtualSecTable(): List[Anomaly] = {
    val table = data.getSectionTable()
    if (table.getOffset() > data.getFile().length()) {
      val description = s"Section Table (offset: ${table.getOffset}) is in virtual space"
      val locations = List(new PhysicalLocation(table.getOffset, table.getSize))
      List(StructureAnomaly(PEStructureKey.SECTION_TABLE, description,
        SEC_TABLE_IN_OVERLAY, locations))
    } else Nil
  }

  private def checkSectionCharacteristics(): List[Anomaly] = {

    def isLastSection(header: SectionHeader): Boolean =
      header.getNumber() == data.getSectionTable().getNumberOfSections()

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
    val loader = new SectionLoader(data)
    for (header <- headers) {
      val sectionName = header.getName
      val characs = header.getCharacteristics.asScala.toList
      val entry = header.getField(SectionHeaderKey.CHARACTERISTICS)
      if (characs.contains(SectionCharacteristic.IMAGE_SCN_MEM_WRITE) && characs.contains(SectionCharacteristic.IMAGE_SCN_MEM_EXECUTE)) {
        val description = s"Section ${header.getNumber} with name ${sectionName} has write and execute characteristics."
        anomalyList += FieldAnomaly(entry, description, WRITE_AND_EXECUTE_SECTION)
      }
      if (characs.size == 1 && characs.contains(SectionCharacteristic.IMAGE_SCN_MEM_WRITE)) {
        val description = s"Section ${header.getNumber} with name ${sectionName} has write as only characteristic"
        anomalyList += FieldAnomaly(entry, description, WRITEABLE_ONLY_SECTION)
      }
      if (characs.size == 0) {
        val description = s"Section ${header.getNumber} with name ${sectionName} has no characteristics"
        anomalyList += FieldAnomaly(entry, description, CHARACTERLESS_SECTION)
      }
      if (loader.containsEntryPoint(header)) {
        if (characs.contains(IMAGE_SCN_MEM_WRITE)) {
          val description = s"Entry point is in writeable section ${header.getNumber} with name ${sectionName}"
          anomalyList += FieldAnomaly(entry, description, EP_IN_WRITEABLE_SEC)
        }
        if (isLastSection(header)) {
          val description = s"Entry point is in the last section ${header.getNumber} with name ${sectionName}"
          anomalyList += FieldAnomaly(entry, description, EP_IN_LAST_SECTION)
        }
      }
      if (charSecNameMap.contains(header.getName)) {
        val mustHaveCharac = charSecNameMap(header.getName)
        //Note: Almost all files don't have IMAGE_SCN_MEM_READ activated, so 
        //this is not an indicator for anything
        val notContainedCharac = mustHaveCharac.filterNot(c => c == IMAGE_SCN_MEM_READ || characs.contains(c))
        val superfluousCharac = characs.filterNot(mustHaveCharac.contains(_))
        if (!notContainedCharac.isEmpty) {
          val description = s"Section Header ${header.getNumber()} with name ${sectionName} should (but doesn't) contain the characteristics: ${notContainedCharac.map(_.shortName).mkString(", ")}"
          anomalyList += FieldAnomaly(entry, description, UNUSUAL_SEC_CHARACTERISTICS)
        }
        if (!superfluousCharac.isEmpty) {
          val description = s"Section Header ${header.getNumber()} with name ${sectionName} has unusual characteristics, that shouldn't be there: ${superfluousCharac.map(_.shortName).mkString(", ")}"
          anomalyList += FieldAnomaly(entry, description, UNUSUAL_SEC_CHARACTERISTICS)
        }
      }
    }
    anomalyList.toList
  }

  private def sectionTableInOverlay(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable
    val overlay = new Overlay(data)
    if (sectionTable.getOffset >= overlay.getOffset &&
      sectionTable.getOffset < data.getFile.length) {
      val description = s"Section Table (offset: ${sectionTable.getOffset}) moved to Overlay"
      val locations = List(new PhysicalLocation(sectionTable.getOffset, sectionTable.getSize))
      anomalyList += StructureAnomaly(PEStructureKey.SECTION_TABLE, description,
        SEC_TABLE_IN_OVERLAY, locations)
    }
    anomalyList.toList
  }

  private def physicalSectionRange(section: SectionHeader): SectionRange = {
    val loader = new SectionLoader(data)
    val start = section.getAlignedPointerToRaw()
    val end = loader.getReadSize(section) + start
    return (start, end)
  }

  private def virtualSectionRange(section: SectionHeader): SectionRange = {
    val start = section.getAlignedVirtualAddress()
    val end = section.getAlignedVirtualSize() + start
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
      val sectionName = section.getName
      if (sectionName != section.getUnfilteredName) {
        val description = s"Section Header ${section.getNumber()} has control symbols in name: ${filteredSymbols(section.getUnfilteredName).mkString(", ")}"
        anomalyList += new SectionNameAnomaly(section, description, CTRL_SYMB_IN_SEC_NAME)
      }
      val packer = packerNames.get(sectionName)
      if(packer.isDefined) {
        val description = s"Section name ${sectionName} is typical for ${packer.get}"
        anomalyList += new SectionNameAnomaly(section, description, UNUSUAL_SEC_NAME)
      }
      else if(sectionName == "") {
        val description = s"Section name of section ${section.getNumber} is empty."
        anomalyList += new SectionNameAnomaly(section, description, EMPTY_SEC_NAME)
      }
      else if (!usualNames.contains(section.getName)) {
        val description = s"Section name is unusual: ${sectionName}"
        anomalyList += new SectionNameAnomaly(section, description, UNUSUAL_SEC_NAME)
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
      val sectionName = section.getName
      val entry = section.getField(SectionHeaderKey.SIZE_OF_RAW_DATA)
      val value = entry.getValue
      val alignedPointerToRaw = section.getAlignedPointerToRaw()
      if (value + alignedPointerToRaw > data.getFile().length()) {
        val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.getKey} + aligned pointer to raw data is larger (${value + alignedPointerToRaw}) than permitted by file length (${data.getFile.length()})"
        anomalyList += FieldAnomaly(entry, description, TOO_LARGE_SIZE_OF_RAW)
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
        val sectionName = section.getName
        val entry = section.getField(SectionHeaderKey.NUMBER_OF_RELOCATIONS)
        val value = entry.getValue
        if (value != 0xffff) {
          val description = s"Section Header ${section.getNumber()} with name ${sectionName}: has IMAGE_SCN_LNK_NRELOC_OVFL characteristic --> ${entry.getKey} must be 0xffff, but is " + value
          anomalyList += FieldAnomaly(entry, description, EXTENDED_RELOC_VIOLATIONS)
        }
      }
    }
    anomalyList.toList
  }

  /**
   * Checks all sections whether they are physically overlapping, shuffled, or a
   * duplicate of each other.
   *
   * @return anomaly list
   */
  private def checkOverlappingOrShuffledSections(): List[Anomaly] = {
    def overlaps(t1: SectionRange, t2: SectionRange): Boolean =
      !(((t1._1 < t2._1) && (t1._2 <= t2._1)) || ((t2._1 < t1._1) && (t2._2 <= t1._1)))

    def notEmpty(range: SectionRange): Boolean = range._1 != range._2

    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable
    val sections = sectionTable.getSectionHeaders.asScala
    for (section <- sections) {
      val sectionName = section.getName
      val range1 = physicalSectionRange(section)
      val vrange1 = virtualSectionRange(section)
      for (i <- section.getNumber() + 1 to sections.length) { //correct?
        val sec = sectionTable.getSectionHeader(i)
        val range2 = physicalSectionRange(sec)
        val vrange2 = virtualSectionRange(sec)
        val locations = List(range1, range2).map(r => new PhysicalLocation(r._1, r._2 - r._1))
        //ignore empty sections for shuffle analysis, these get their own anomaly
        if (range1._1 > range2._1 && notEmpty(range1) && notEmpty(range2)) {
          val description = s"Physically shuffled sections: section ${section.getNumber()} has range ${range1._1}--${range1._2}, section ${sec.getNumber()} has range ${range2._1}--${range2._2}"
          anomalyList += StructureAnomaly(PEStructureKey.SECTION, description, PHYSICALLY_SHUFFLED_SEC, locations)
        }
        if (range1 == range2) {
          val description = s"Section ${section.getNumber()} with name ${sectionName} (range: ${range1._1}--${range1._2}) has same physical location as section ${sec.getNumber()} with name ${sec.getName}"
          anomalyList += StructureAnomaly(PEStructureKey.SECTION, description, PHYSICALLY_DUPLICATED_SEC, locations)
        } else if (overlaps(range2, range1)) {
          val description = s"Section ${section.getNumber()} with name ${sectionName} (range: ${range1._1}--${range1._2}) physically overlaps with section ${sec.getName} with number ${sec.getNumber} (range: ${range2._1}--${range2._2})"
          anomalyList += StructureAnomaly(PEStructureKey.SECTION, description, PHYSICALLY_OVERLAPPING_SEC, locations)
        }
        if (vrange1 == vrange2) {
          val description = s"Section ${section.getNumber()} with name ${sectionName} (range: ${vrange1._1}--${vrange1._2}) has same virtual location as section ${sec.getName} with number ${sec.getNumber} (range: ${vrange2._1}--${vrange2._2})"
          anomalyList += StructureAnomaly(PEStructureKey.SECTION, description, VIRTUALLY_DUPLICATED_SEC, locations)
        } else if (overlaps(vrange1, vrange2)) {
          val description = s"Section ${section.getNumber()} with name ${sectionName} (range: ${vrange1._1}--${vrange1._2}) virtually overlaps with section ${sec.getName} with number ${sec.getNumber} (range: ${vrange2._1}--${vrange2._2})"
          anomalyList += StructureAnomaly(PEStructureKey.SECTION, description, VIRTUALLY_OVERLAPPING_SEC, locations)
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
      val sectionName = section.getName
      val entry = section.getField(SectionHeaderKey.VIRTUAL_ADDRESS)
      val sectionVA = entry.getValue
      if (sectionVA <= prevVA) {
        val range = physicalSectionRange(section)
        val locations = List(new PhysicalLocation(range._1, range._2 - range._1))
        val description = s"Section Header ${section.getNumber()} with name ${sectionName}: VIRTUAL_ADDRESS (${sectionVA}) should be greater than of the previous entry (${prevVA})"
        anomalyList += StructureAnomaly(PEStructureKey.SECTION, description, NOT_ASCENDING_SEC_VA, locations)
      }
    }
    anomalyList.toList
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
      val sectionName = section.getName
      characteristics.foreach(ch =>
        if (ch.isReserved) {
          val description = s"Section Header ${section.getNumber()} with name ${sectionName}: Reserved characteristic used: ${ch.toString}"
          anomalyList += FieldAnomaly(entry, description, RESERVED_SEC_CHARACTERISTICS)
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
      val sectionName = section.getName
      val characteristics = section.getCharacteristics().asScala
      for (ch <- characteristics if ch.isDeprecated) {
        val entry = section.getField(SectionHeaderKey.CHARACTERISTICS)
        val description = s"Section Header ${section.getNumber()} with name ${sectionName}: Characteristic ${ch.toString} is deprecated"
        anomalyList += FieldAnomaly(entry, description, DEPRECATED_SEC_CHARACTERISTICS)
      }
      for (entry <- List(ptrLineNrEntry, lineNrEntry) if entry.getValue != 0) {
        val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.getKey} is deprecated, but has value " + entry.getValue
        val subtype = if (entry.getKey == SectionHeaderKey.POINTER_TO_LINE_NUMBERS)
          DEPRECATED_PTR_OF_LINE_NR
        else DEPRECATED_NR_OF_LINE_NR
        anomalyList += FieldAnomaly(entry, description, subtype)
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
      val sectionName = section.getName
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
    for (entry <- List(sizeOfRaw, virtSize) if entry.getValue == 0) {
      val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.getKey} is ${entry.getValue}"
      val subtype = if (entry.getKey == SectionHeaderKey.VIRTUAL_SIZE)
        ZERO_VIRTUAL_SIZE
      else ZERO_SIZE_OF_RAW_DATA
      anomalyList += FieldAnomaly(entry, description, subtype)
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
      for (entry <- List(sizeEntry, pointerEntry) if entry.getValue != 0) {
        val value = entry.getValue
        val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.getKey.toString} must be 0 for sections with only uninitialized data, but is: ${value}"
        anomalyList += FieldAnomaly(entry, description, UNINIT_DATA_CONSTRAINTS_VIOLATION)
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
      val sectionName = section.getName
      for (
        entry <- List(sizeEntry, pointerEntry) if entry != null &&
          fileAlignment != 0 && entry.getValue % fileAlignment != 0
      ) {
        val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.getKey} (${entry.getValue}) must be a multiple of File Alignment (${fileAlignment})"
        val subtype = if (entry.getKey == SectionHeaderKey.SIZE_OF_RAW_DATA)
          NOT_FILEALIGNED_SIZE_OF_RAW
        else NOT_FILEALIGNED_PTR_TO_RAW
        anomalyList += FieldAnomaly(entry, description, subtype)
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
    val alignmentCharacteristics = SectionCharacteristic.values.filter(k => k.toString.startsWith("IMAGE_SCN_ALIGN")).toList
    val objectOnly = List(IMAGE_SCN_TYPE_NO_PAD, IMAGE_SCN_LNK_INFO, IMAGE_SCN_LNK_REMOVE, IMAGE_SCN_LNK_COMDAT) ::: alignmentCharacteristics
    for (characteristic <- section.getCharacteristics().asScala if objectOnly.contains(characteristic)) {
      val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${characteristic} characteristic is only valid for object files"
      val chEntry = section.getField(SectionHeaderKey.CHARACTERISTICS)
      anomalyList += FieldAnomaly(chEntry, description, OBJECT_ONLY_SEC_CHARACTERISTICS)
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
    for (entry <- List(relocEntry, nrRelocEntry) if entry.getValue != 0) {
      val description = s"Section Header ${section.getNumber()} with name ${sectionName}: ${entry.getKey} should be 0 for images, but has value " + entry.getValue
      val subtype = if (entry.getKey == SectionHeaderKey.NUMBER_OF_RELOCATIONS)
        DEPRECATED_NR_OF_RELOC
      else DEPRECATED_PTR_TO_RELOC
      anomalyList += FieldAnomaly(entry, description, subtype)
    }
  }
}
