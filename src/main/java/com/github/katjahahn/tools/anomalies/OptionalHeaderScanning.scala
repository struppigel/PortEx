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
import java.util.Map
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.optheader.Subsystem
import com.github.katjahahn.parser.optheader.OptionalHeader
import com.github.katjahahn.parser.optheader.WindowsEntryKey
import com.github.katjahahn.parser.PESignature
import com.github.katjahahn.parser.sections.SectionHeaderKey
import com.github.katjahahn.parser.sections.SectionTable
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.coffheader.COFFFileHeader
import com.github.katjahahn.parser.optheader.StandardFieldEntryKey
import com.github.katjahahn.parser.optheader.DataDirectoryKey
import com.github.katjahahn.parser.optheader.DllCharacteristic
import com.github.katjahahn.parser.coffheader.FileCharacteristic
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.Location
import com.github.katjahahn.parser.PhysicalLocation

/**
 * Scans the Optional Header for anomalies.
 *
 * @author Katja Hahn
 */
trait OptionalHeaderScanning extends AnomalyScanner {

  abstract override def scanReport(): String =
    "Applied Optional Header Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val opt = data.getOptionalHeader()
    val anomalyList = ListBuffer[Anomaly]()
    if (opt == null) return Nil
    anomalyList ++= dataDirScan(opt)
    anomalyList ++= windowsFieldScan(opt)
    anomalyList ++= standardFieldScan(opt)
    anomalyList ++= dupHeadScan(opt)
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
    checkEntryPoint(opt)
  }

  /**
   * Checks for entry point anomalies.
   *
   * @param opt optional header
   * @return anomaly list
   */
  private def checkEntryPoint(opt: OptionalHeader): List[Anomaly] = {
    def isLowAlignment(secAlign: Long, fileAlign: Long): Boolean =
      1 <= fileAlign && fileAlign == secAlign && secAlign <= 0x800
    def isVirtual(ep: Long): Boolean = {
      val sectionHeaders = data.getSectionTable().getSectionHeaders().asScala
      val addresses = sectionHeaders.map(_.get(SectionHeaderKey.VIRTUAL_ADDRESS)).filter(_ != 0)
      if (addresses.size > 0)
        ep < addresses.min
      else false
    }
    val anomalyList = ListBuffer[Anomaly]()
    val ep = opt.get(StandardFieldEntryKey.ADDR_OF_ENTRY_POINT)
    val sizeOfHeaders = opt.get(WindowsEntryKey.SIZE_OF_HEADERS)
    val entry = opt.getStandardFieldEntry(StandardFieldEntryKey.ADDR_OF_ENTRY_POINT)
    if (ep == 0 && !isDLL) {
      val description = s"Optional Header: address of entry point is ${ep}, but PE is no DLL"
      anomalyList += FieldAnomaly(entry, description, ZERO_EP)
    }
    if (ep != 0 && ep < sizeOfHeaders) {
      val description = s"Optional Header: address of entry point (${ep}) is smaller than size of headers (${sizeOfHeaders})"
      anomalyList += FieldAnomaly(entry, description, TOO_SMALL_EP)
    }
    if (isVirtual(ep)) { //TODO add more virtual entry point anomalies
      val description = s"Optional Header: virtual entry point (${ep}): starts in virtual space before any section"
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
    def isLowAlignment(secAlign: Long, fileAlign: Long): Boolean =
      1 <= fileAlign && fileAlign == secAlign && secAlign <= 0x800
    val anomalyList = ListBuffer[Anomaly]()
    val sectionAlignment = opt.get(WindowsEntryKey.SECTION_ALIGNMENT)
    val fileAlignment = opt.get(WindowsEntryKey.FILE_ALIGNMENT)
    if (isLowAlignment(sectionAlignment, fileAlignment)) {
      val entry = opt.getWindowsFieldEntry(WindowsEntryKey.FILE_ALIGNMENT)
      val description = s"Optional Header: Low alignment mode, section alignment = ${sectionAlignment}, file alignment = ${fileAlignment}"
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
      val description = s"Optional Header: Size of Image (${imageSize}) must be a multiple of Section Alignment (${sectionAlignment})"
      anomalyList += FieldAnomaly(entry, description, NOT_SEC_ALIGNED_SIZE_OF_IMAGE)
    }
    val headerSizeEntry = opt.getWindowsFieldEntry(WindowsEntryKey.SIZE_OF_HEADERS)
    if (fileAlignment != 0 && headerSize % fileAlignment != 0) {
      val description = s"Optional Header: Size of Headers (${headerSize}) must be a multiple of File Alignment (${fileAlignment})"
      anomalyList += FieldAnomaly(headerSizeEntry, description, NOT_FILEALIGNED_SIZE_OF_HEADERS)
    } //TODO headerSize >= MSDOS + PEHeader + Section Headers size
    if (headerSize < headerSizeMin) {
      val description = s"Optional Header: Possibly Dual PE Header malformation. Size of Headers should be greater than or equal to ${headerSizeMin}, but is ${headerSize}."
      anomalyList += FieldAnomaly(headerSizeEntry, description, TOO_SMALL_SIZE_OF_HEADERS)
    }
    if (headerSize != roundedUpHeaderSize) {
      val description = s"Optional Header: Size of Headers should be ${roundedUpHeaderSize}, but is ${headerSize}"
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
      val description = "Optional Header: File Alignment must be a power of 2, but is " + fileAlignment
      anomalyList += FieldAnomaly(entry, description, NOT_POW_OF_TWO_FILEALIGN)
    }
    if (fileAlignment < 512 || fileAlignment > 65536) {
      val description = "Optional Header: File Alignment must be between 512 and 64 K, but is " + fileAlignment
      val subtype = if (fileAlignment < 512) TOO_SMALL_FILEALIGN else TOO_LARGE_FILEALIGN
      anomalyList += FieldAnomaly(entry, description, subtype)
    }
    if (fileAlignment != 512) {
      val description = "Optional Header: Default File Alignment is 512, but actual value is " + fileAlignment
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
      val description = s"Optional Header: Section Alignment (${sectionAlignment}) needs to be >= File Alignment (${fileAlignment})"
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
      val description = s"Optional Header: ImageBase + SizeOfImage is too large (${imageBase + sizeOfImage}), thus relocated to 0x10000"
      anomalyList += FieldAnomaly(entry, description, TOO_LARGE_IMAGE_BASE)
    }
    if (imageBase == 0) {
      val description = "Optional Header: The image base is 0, thus relocated to 0x10000"
      anomalyList += FieldAnomaly(entry, description, ZERO_IMAGE_BASE)
    }
    if (isDLL() && imageBase != 0x10000000L) {
      val description = "Optional Header: The default image base for a DLL is 0x10000000, but actual value is 0x" + java.lang.Long.toHexString(imageBase)
      anomalyList += FieldAnomaly(entry, description, NON_DEFAULT_IMAGE_BASE)
    } else if (isWinCE() && imageBase != 0x00010000L) {
      val description = "Optional Header: The default image base for Win CE EXE is 0x00010000, but actual value is 0x" + java.lang.Long.toHexString(imageBase)
      anomalyList += FieldAnomaly(entry, description, NON_DEFAULT_IMAGE_BASE)
    } else if (imageBase != 0x00400000L) { //TODO
      val description = "Optional Header: The default image base is 0x00400000, but actual value is 0x" + java.lang.Long.toHexString(imageBase)
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
        val description = "Optional Header: NumberOfRVAAndSizes has unusual value: " + entry.getValue
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
        val description = s"Optional Header: Invalid Data Directory Entry ${datadir.getKey}, entry points outside of file"
        anomalyList += DataDirAnomaly(datadir, description,
          INVALID_DATA_DIR)
      }
    }
    anomalyList.toList
  }

}
