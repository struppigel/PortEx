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
package com.github.struppigel.tools.anomalies

import com.github.struppigel.parser.IOUtil._
import AnomalySubType._
import com.github.struppigel.parser.PhysicalLocation
import com.github.struppigel.parser.coffheader.FileCharacteristic
import com.github.struppigel.parser.optheader.{DataDirectoryKey, OptionalHeader, StandardFieldEntryKey, Subsystem, WindowsEntryKey}
import com.github.struppigel.parser.sections.{SectionCharacteristic, SectionLoader}

import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer

/**
 * Scans the Optional Header for anomalies.
 *
 * @author Karsten Hahn
 */
trait OptionalHeaderScanning extends AnomalyScanner {

  abstract override def scanReport(): String =
    "Applied Optional Header Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val opt = data.getOptionalHeader()
    val anomalyList = ListBuffer[Anomaly]()
    if (opt != null) {
      anomalyList ++= dataDirScan(opt)
      anomalyList ++= windowsFieldScan(opt)
      anomalyList ++= standardFieldScan(opt)
      anomalyList ++= dupHeadScan(opt)
    }
    super.scan ::: anomalyList.toList
  }

  private def dupHeadScan(opt: OptionalHeader): List[Anomaly] = {
    val sizeOfHeaders = opt.get(WindowsEntryKey.SIZE_OF_HEADERS)
    if (sizeOfHeaders < headerSizeMin) {
      val description = "Possible Duplicated Header: SizeOfHeaders smaller than actual header size"
      val subtype = AnomalySubType.DUPLICATED_PE_FILE_HEADER
      val locations = List(new PhysicalLocation(sizeOfHeaders, headerSizeMin))
      List(new StructureAnomaly(PEStructureKey.PE_FILE_HEADER, description, subtype, locations))
    } else Nil
  }

  /**
   * Scans all Windows specific fields for anomalies.
   *
   * @param opt optional header
   * @return anomaly list
   */
  private def windowsFieldScan(opt: OptionalHeader): List[Anomaly] = {
    checkImageBase(opt) ::: checkSectionAlignment(opt) :::
      checkFileAlignment(opt) ::: checkLowAlignment(opt) :::
      checkReservedAndDeprecated(opt) ::: checkSizes(opt)
  }

  /**
   * Scans all standard fields for anomalies.
   *
   * @param opt optional header
   * @return anomaly list
   */
  private def standardFieldScan(opt: OptionalHeader): List[Anomaly] = {
    checkEntryPoint(opt) ::: checkStandardFieldSizes(opt)
  }

  /**
   * @return sum of the size of all sections that have characteristic ch, in bytes
   */
  private def calculateSizeOfSectionsWith(chara: SectionCharacteristic): Long = {
    val sectionTable = data.getSectionTable
    val loader = new SectionLoader(data)
    val sections = sectionTable.getSectionHeaders.asScala
    //calculate sum of readsizes
    sections.foldRight[Long](0L)((section, size) =>
      if (section.getCharacteristics.contains(chara))
        loader.getReadSize(section) + size
      else size)
  }

  private def checkStandardFieldSizes(opt: OptionalHeader): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sizeOfCode = opt.getStandardFieldEntry(StandardFieldEntryKey.SIZE_OF_CODE)
    val actualSizeOfCode = calculateSizeOfSectionsWith(SectionCharacteristic.IMAGE_SCN_CNT_CODE)
    if (sizeOfCode.getValue > actualSizeOfCode) {
      val description = s"Optional Header: size of code is too large (${hexString(sizeOfCode.getValue)}), it should be ${hexString(actualSizeOfCode)}"
      anomalyList += FieldAnomaly(sizeOfCode, description, TOO_LARGE_SIZE_OF_CODE)
    } else if (sizeOfCode.getValue < actualSizeOfCode) { 
      val description = s"Optional Header: size of code is too small (${hexString(sizeOfCode.getValue)}), it should be ${hexString(actualSizeOfCode)}"
      anomalyList += FieldAnomaly(sizeOfCode, description, TOO_SMALL_SIZE_OF_CODE)
    }
    
    val sizeOfInitData = opt.getStandardFieldEntry(StandardFieldEntryKey.SIZE_OF_INIT_DATA)
    val actualSizeOfInitData = calculateSizeOfSectionsWith(SectionCharacteristic.IMAGE_SCN_CNT_INITIALIZED_DATA)
    if (sizeOfInitData.getValue > actualSizeOfInitData) {
      val description = s"Optional Header: size of initialized data is too large (${hexString(sizeOfInitData.getValue)}), it should be ${hexString(actualSizeOfInitData)}"
      anomalyList += FieldAnomaly(sizeOfInitData, description, TOO_LARGE_SIZE_OF_INIT_DATA)
    } else if (sizeOfInitData.getValue < actualSizeOfInitData) {
      val description = s"Optional Header: size of initialized data is too small (${hexString(sizeOfInitData.getValue)}), it should be ${hexString(actualSizeOfInitData)}"
      anomalyList += FieldAnomaly(sizeOfInitData, description, TOO_SMALL_SIZE_OF_INIT_DATA)
    }
    
    val sizeOfUninitData = opt.getStandardFieldEntry(StandardFieldEntryKey.SIZE_OF_UNINIT_DATA)
    val actualSizeOfUninitData = calculateSizeOfSectionsWith(SectionCharacteristic.IMAGE_SCN_CNT_UNINITIALIZED_DATA)
    if (sizeOfUninitData.getValue > actualSizeOfUninitData) {
      val description = s"Optional Header: size of uninitialized data is too large (${hexString(sizeOfUninitData.getValue)}), it should be ${hexString(actualSizeOfUninitData)}"
      anomalyList += FieldAnomaly(sizeOfUninitData, description, TOO_LARGE_SIZE_OF_UNINIT_DATA)
    } else if (sizeOfUninitData.getValue < actualSizeOfUninitData) {
      val description = s"Optional Header: size of uninitialized data is too small, namely ${hexString(sizeOfUninitData.getValue)}"
      anomalyList += FieldAnomaly(sizeOfUninitData, description, TOO_SMALL_SIZE_OF_UNINIT_DATA)
    }
    
    val sizeOfImage = opt.get(WindowsEntryKey.SIZE_OF_IMAGE)
    val maybeBaseOfData = opt.maybeGetStandardFieldEntry(StandardFieldEntryKey.BASE_OF_DATA)
    if(maybeBaseOfData.isPresent) {
     val baseOfData = maybeBaseOfData.get;
     if(actualSizeOfInitData + actualSizeOfUninitData > 0 && baseOfData.getValue == 0L) {
        val description = s"Optional Header: base of data is zero although data section exists"
        anomalyList += FieldAnomaly(baseOfData, description, ZERO_BASE_OF_DATA)
      } else if (baseOfData.getValue > sizeOfImage) {
        val description = s"Optional Header: base of data is too large, namely ${hexString(baseOfData.getValue)}"
        anomalyList += FieldAnomaly(baseOfData, description, TOO_LARGE_BASE_OF_DATA)
      }
    }
    
    val baseOfCode = opt.getStandardFieldEntry(StandardFieldEntryKey.SIZE_OF_INIT_DATA)
    if(actualSizeOfCode > 0 && baseOfCode.getValue == 0L) {
      val description = s"Optional Header: base of code is zero although code section exists"
      anomalyList += FieldAnomaly(baseOfCode, description, ZERO_BASE_OF_CODE)
    } else if (baseOfCode.getValue > sizeOfImage) {
      val description = s"Optional Header: base of code is too large, namely ${hexString(baseOfCode.getValue)}"
      anomalyList += FieldAnomaly(baseOfCode, description, TOO_LARGE_BASE_OF_CODE)
    }
    anomalyList.toList
  }

  /**
   * Checks for entry point anomalies.
   *
   * @param opt optional header
   * @return anomaly list
   */
  private def checkEntryPoint(opt: OptionalHeader): List[Anomaly] = {
    def isVirtual(ep: Long): Boolean = {
      val maybeSec = new SectionLoader(data).maybeGetSectionHeaderByRVA(ep)
      !maybeSec.isPresent
      /*
      val secTable = data.getSectionTable()
      val sectionHeaders = secTable.getSectionHeaders().asScala
      val addresses = sectionHeaders.map(_.get(SectionHeaderKey.VIRTUAL_ADDRESS)).filter(_ != 0)
      if (addresses.size > 0)
        ep < addresses.min
      else false
      */
    }
    val anomalyList = ListBuffer[Anomaly]()
    val ep = opt.get(StandardFieldEntryKey.ADDR_OF_ENTRY_POINT)
    val sizeOfHeaders = opt.get(WindowsEntryKey.SIZE_OF_HEADERS)
    val entry = opt.getStandardFieldEntry(StandardFieldEntryKey.ADDR_OF_ENTRY_POINT)
    if (ep == 0 && !isDLL) {
      val description = s"Optional Header: address of entry point is ${hexString(ep)}, but PE is no DLL"
      anomalyList += FieldAnomaly(entry, description, ZERO_EP)
    }
    if (ep != 0 && ep < sizeOfHeaders) {
      val description = s"Optional Header: address of entry point (${hexString(ep)}) is smaller than size of headers (${hexString(sizeOfHeaders)})"
      anomalyList += FieldAnomaly(entry, description, TOO_SMALL_EP)
    }
    if (isVirtual(ep)) {
      val description = s"Optional Header: virtual entry point (${hexString(ep)}), it does not point to a section."
      anomalyList += FieldAnomaly(entry, description, VIRTUAL_EP)
    }

    anomalyList.toList
  }

  /**
   * Checks for low alignment mode.
   *
   * @param opt optional header
   * @return anomaly list
   */
  private def checkLowAlignment(opt: OptionalHeader): List[Anomaly] = {
    //see: https://code.google.com/p/corkami/wiki/PE#SectionAlignment_/_FileAlignment
    val anomalyList = ListBuffer[Anomaly]()
    val sectionAlignment = opt.get(WindowsEntryKey.SECTION_ALIGNMENT)
    val fileAlignment = opt.get(WindowsEntryKey.FILE_ALIGNMENT)
    if (opt.isLowAlignmentMode) {
      val entry = opt.getWindowsFieldEntry(WindowsEntryKey.FILE_ALIGNMENT)
      val description = s"Optional Header: Low alignment mode, section alignment = ${hexString(sectionAlignment)}, file alignment = ${hexString(fileAlignment)}"
      anomalyList += FieldAnomaly(entry, description, LOW_ALIGNMENT_MODE)
    }
    anomalyList.toList
  }

  /**
   * Checks SizeOfImage and SizeOfHeaders for correct alignment and min/max constraints
   *
   * @param opt optional header
   * @return anomaly list
   */
  private def checkSizes(opt: OptionalHeader): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val imageSize = opt.get(WindowsEntryKey.SIZE_OF_IMAGE)
    val headerSize = opt.get(WindowsEntryKey.SIZE_OF_HEADERS)
    val sectionAlignment = opt.get(WindowsEntryKey.SECTION_ALIGNMENT)
    val fileAlignment = opt.get(WindowsEntryKey.FILE_ALIGNMENT)
    if (sectionAlignment != 0 && imageSize % sectionAlignment != 0) {
      val entry = opt.getWindowsFieldEntry(WindowsEntryKey.SIZE_OF_IMAGE)
      val description = s"Optional Header: Size of Image (${hexString(imageSize)}) must be a multiple of Section Alignment (${hexString(sectionAlignment)})"
      anomalyList += FieldAnomaly(entry, description, NOT_SEC_ALIGNED_SIZE_OF_IMAGE)
    }
    val headerSizeEntry = opt.getWindowsFieldEntry(WindowsEntryKey.SIZE_OF_HEADERS)
    if (fileAlignment != 0 && headerSize % fileAlignment != 0) {
      val description = s"Optional Header: Size of Headers (${hexString(headerSize)}) must be a multiple of File Alignment (${hexString(fileAlignment)})"
      anomalyList += FieldAnomaly(headerSizeEntry, description, NOT_FILEALIGNED_SIZE_OF_HEADERS)
    } //TODO headerSize >= MSDOS + PEHeader + Section Headers size
    if (headerSize < headerSizeMin) {
      val description = s"Optional Header: Possibly Dual PE Header malformation. Size of Headers should be greater than or equal to ${hexString(headerSizeMin)}, but is ${hexString(headerSize)}."
      anomalyList += FieldAnomaly(headerSizeEntry, description, TOO_SMALL_SIZE_OF_HEADERS)
    }
    if (headerSize != roundedUpHeaderSize) {
      val description = s"Optional Header: Size of Headers should be ${hexString(roundedUpHeaderSize)}, but is ${hexString(headerSize)}"
      anomalyList += FieldAnomaly(headerSizeEntry, description, NON_DEFAULT_SIZE_OF_HEADERS)
    }
    anomalyList.toList
  }

  /**
   * Returns the minimum value for the SizeOfHeader based on the section table
   * offset plus size. No alignment is taken into account.
   *
   * @return the minimum header size
   */
  private def headerSizeMin(): Long =
    data.getSectionTable().getOffset() + data.getSectionTable().getSize()

  /**
   * Rounds up the header size minimum to a multiple of FileAlignment.
   *
   * @return aligned SizeOfHeaders value as it should be
   */
  private def roundedUpHeaderSize(): Long = {
    val fileAlignment = data.getOptionalHeader().get(WindowsEntryKey.FILE_ALIGNMENT)
    if (fileAlignment != 0 && (headerSizeMin % fileAlignment) != 0) {
      (fileAlignment - (headerSizeMin % fileAlignment)) + headerSizeMin
    } else headerSizeMin
  }

  /**
   * Checks for reserved entries in the windows specific fields, including
   * DLLCharacteristics, LoaderFlags, Win32VersionValue
   *
   * @param opt optional header
   * @return anomaly list
   */
  private def checkReservedAndDeprecated(opt: OptionalHeader): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val win32version = opt.get(WindowsEntryKey.WIN32_VERSION_VALUE)
    val loaderFlags = opt.get(WindowsEntryKey.LOADER_FLAGS)
    val dllChs = opt.getDllCharacteristics().asScala
    for (ch <- dllChs if ch.isReserved || ch.isDeprecated) {
      val entry = opt.getWindowsFieldEntry(WindowsEntryKey.DLL_CHARACTERISTICS)
      if (ch.isReserved) {
        val description = s"Optional Header: Reserved DllCharacteristic ${ch.toString()} is not 0"
        List(FieldAnomaly(entry, description, RESERVED_DLL_CHARACTERISTICS))
      } else {
        val description = s"Optional Header: Deprecated DllCharacteristic ${ch.toString()} is not 0"
        List(FieldAnomaly(entry, description, RESERVED_DLL_CHARACTERISTICS))
      }
    }
    if (win32version != 0) {
      val description = "Optional Header: Reserved WIN32_VERSION_VALUE is not 0, but " + win32version
      val entry = opt.getWindowsFieldEntry(WindowsEntryKey.WIN32_VERSION_VALUE)
      List(FieldAnomaly(entry, description, RESERVED_WIN32VERSION))
    }
    if (loaderFlags != 0) {
      val description = "Optional Header: Reserved LOADER_FLAGS is not 0, but " + loaderFlags
      val entry = opt.getWindowsFieldEntry(WindowsEntryKey.LOADER_FLAGS)
      List(FieldAnomaly(entry, description, RESERVED_LOADER_FLAGS))
    }
    anomalyList.toList
  }

  /**
   * Checks the FileAlignment field for min, max and default values and
   * verifies if it is a power of two.
   *
   * @param opt optional header
   * @return anomaly list
   */
  private def checkFileAlignment(opt: OptionalHeader): List[Anomaly] = {
    def isPowerOfTwo(x: Long): Boolean = (x != 0) && ((x & (x - 1)) == 0)
    val anomalyList = ListBuffer[Anomaly]()
    val sectionAlignment = opt.get(WindowsEntryKey.SECTION_ALIGNMENT)
    val entry = opt.getWindowsFieldEntry(WindowsEntryKey.FILE_ALIGNMENT)
    val fileAlignment = entry.getValue
    if (!isPowerOfTwo(fileAlignment)) {
      val description = "Optional Header: File Alignment must be a power of 2, but is " + hexString(fileAlignment)
      anomalyList += FieldAnomaly(entry, description, NOT_POW_OF_TWO_FILEALIGN)
    }
    if (fileAlignment < 512 || fileAlignment > 65536) {
      val description = "Optional Header: File Alignment must be between 0x200 and 0xFA00 (64 K), but is " + hexString(fileAlignment)
      val subtype = if (fileAlignment < 512) TOO_SMALL_FILEALIGN else TOO_LARGE_FILEALIGN
      anomalyList += FieldAnomaly(entry, description, subtype)
    }
    if (fileAlignment != 512) {
      val description = "Optional Header: Default File Alignment is 0x200, but actual value is " + hexString(fileAlignment)
      anomalyList += FieldAnomaly(entry, description, NON_DEFAULT_FILEALIGN)
    }
    anomalyList.toList
  }

  /**
   * Checks the section alignment for constraints, like section alignment being
   * larger than or equal to file alignment.
   *
   * @param opt optional header
   * @return anomaly list
   */
  private def checkSectionAlignment(opt: OptionalHeader): List[Anomaly] = {
    val sectionAlignment = opt.get(WindowsEntryKey.SECTION_ALIGNMENT)
    val fileAlignment = opt.get(WindowsEntryKey.FILE_ALIGNMENT)
    if (sectionAlignment < fileAlignment) {
      val description = s"Optional Header: Section Alignment (${hexString(sectionAlignment)}) needs to be >= File Alignment (${hexString(fileAlignment)})"
      val entry = opt.getWindowsFieldEntry(WindowsEntryKey.SECTION_ALIGNMENT)
      List(FieldAnomaly(entry, description, TOO_SMALL_SECALIGN))
    } else Nil
  }

  /**
   * Checks image base constraints, including default values according to the
   * specification, multiple of 64 K, zero value, too large value
   *
   * @param opt optional header
   * @return anomaly list
   */
  private def checkImageBase(opt: OptionalHeader): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val entry = opt.getWindowsFieldEntry(WindowsEntryKey.IMAGE_BASE)
    val imageBase = entry.getValue
    val sizeOfImage = opt.get(WindowsEntryKey.SIZE_OF_IMAGE)
    if (imageBase % 65536 != 0) {
      val description = "Optional Header: Image Base must be a multiple of 64 K, but is " + imageBase
      anomalyList += FieldAnomaly(entry, description, NOT_MULT_OF_64K_IMAGE_BASE)
    }
    if ((imageBase + sizeOfImage) >= 0x80000000L) {
      val description = s"Optional Header: ImageBase + SizeOfImage is too large (${hexString(imageBase + sizeOfImage)}), thus relocated to 0x10000"
      anomalyList += FieldAnomaly(entry, description, TOO_LARGE_IMAGE_BASE)
    }
    if (imageBase == 0) {
      val description = "Optional Header: The image base is 0, thus relocated to 0x10000"
      anomalyList += FieldAnomaly(entry, description, ZERO_IMAGE_BASE)
    }
    if (isDLL()) {
      if(imageBase != 0x10000000L){
        val description = "Optional Header: The default image base for a DLL is 0x10000000, but actual value is " + hexString(imageBase)
        anomalyList += FieldAnomaly(entry, description, NON_DEFAULT_IMAGE_BASE)
      }
    } else if (isWinCE()) {
      if( imageBase != 0x00010000L) {
        val description = "Optional Header: The default image base for Win CE EXE is 0x00010000, but actual value is " + hexString(imageBase)
        anomalyList += FieldAnomaly(entry, description, NON_DEFAULT_IMAGE_BASE)
      }
    } else if (imageBase != 0x00400000L) {
      val description = "Optional Header: The default image base is 0x00400000, but actual value is " + hexString(imageBase)
      anomalyList += FieldAnomaly(entry, description, NON_DEFAULT_IMAGE_BASE)
    }
    anomalyList.toList
  }

  /**
   * @return true iff the current optional header has the
   * IMAGE_SUBSYSTEM_WINDOWS_CE_GUI subsystem set.
   */
  private def isWinCE(): Boolean =
    data.getOptionalHeader().getSubsystem() == Subsystem.IMAGE_SUBSYSTEM_WINDOWS_CE_GUI

  /**
   * @return true iff the current coff file header has the IMAGE_FILE_DLL
   * characteristic set
   */
  private def isDLL(): Boolean =
    data.getCOFFFileHeader().getCharacteristics().contains(FileCharacteristic.IMAGE_FILE_DLL)
    
  private def hexString(value: Long): String =
    "0x" + java.lang.Long.toHexString(value)

  /**
   * Scans the data directories for anomalies, including number of entries and
   * reserved entries.
   *
   * @param opt optional header
   * @return anomaly list
   */
  private def dataDirScan(opt: OptionalHeader): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val datadirs = opt.getDataDirectory()
    if (datadirs.size() != 16) {
      val entry = opt.getWindowsFieldEntry(WindowsEntryKey.NUMBER_OF_RVA_AND_SIZES)
      if (entry.getValue == 0) {
        val locations = List(new PhysicalLocation(entry.getOffset(), entry.getSize()))
        val description = "Optional Header: No data directory present"
        anomalyList += StructureAnomaly(PEStructureKey.DATA_DIRECTORY, description, NO_DATA_DIR, locations)
      }
      if (entry.getValue != 16) {
        val description = s"Optional Header: NumberOfRVAAndSizes has an unusual value (${hexString(entry.getValue)}), it should be 0x10"
        anomalyList += FieldAnomaly(entry, description, UNUSUAL_DATA_DIR_NR)
      }
    }
    if (datadirs.containsKey(DataDirectoryKey.RESERVED)) {
      val entry = datadirs.get(DataDirectoryKey.RESERVED)
      val description = "Reserved Data Directory Entry is not 0. Entry --> " + NL + entry.toString
      anomalyList += DataDirAnomaly(entry, description, RESERVED_DATA_DIR)
    }
    if (datadirs.containsKey(DataDirectoryKey.ARCHITECTURE)) {
      val entry = datadirs.get(DataDirectoryKey.ARCHITECTURE)
      val description = "Reserved Data Directory Entry is not 0. Entry --> " + NL + entry.toString
      anomalyList += DataDirAnomaly(entry, description, RESERVED_DATA_DIR)
    }
    if (datadirs.containsKey(DataDirectoryKey.GLOBAL_PTR) &&
      datadirs.get(DataDirectoryKey.GLOBAL_PTR).getDirectorySize() != 0) {
      val entry = datadirs.get(DataDirectoryKey.GLOBAL_PTR)
      val description = "Global Ptr Data Directory size is not 0, but should be"
      anomalyList += DataDirAnomaly(entry, description, GLOBAL_PTR_SIZE_SET)
    }
    for (datadir <- datadirs.values().asScala) {
      def isValid: Boolean = {
        val secTable = data.getSectionTable
        val fileOffset = datadir.getFileOffset(secTable)
        fileOffset >= 0 && fileOffset < data.getFile.length
      }
      val loader = new SectionLoader(data)
      if (!isValid) {
        val description = s"Optional Header: invalid data directory entry for ${datadir.getKey}, its entry points outside of the file"
        anomalyList += DataDirAnomaly(datadir, description,INVALID_DATA_DIR)
      }
    }
    anomalyList.toList
  }

}
