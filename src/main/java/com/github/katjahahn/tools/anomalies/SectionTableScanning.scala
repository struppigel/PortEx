package com.github.katjahahn.tools.anomalies

import scala.collection.mutable.ListBuffer
import com.github.katjahahn.optheader.WindowsEntryKey
import scala.collection.JavaConverters._
import com.github.katjahahn.sections.SectionTableEntryKey
import sun.security.krb5.internal.crypto.DesCbcCrcEType

trait SectionTableScanning extends AnomalyScanner {

  //TODO ascending order of VAs
  //multiple of FileAlignment SIZE_OF_RAW_DATA (for executable images only) and zero if only unitialized data
  //multiple of FileAlignment POINTER_TO_RAW_DATA  and zero if only uninitialized data
  //POINTER_TO_RELOC, NumberOfRelocations zero for executables
  //PointerToLinenumbers, NumberOfLinenumbers zero for images (COFF debugging deprecated)
  //Reserved section characteristic flags
  
  abstract override def scan(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    anomalyList ++= checkFileAlignmentConstrains()
    anomalyList ++= checkDeprecated() 
    super.scan ::: anomalyList.toList
  }
  
  private def checkDeprecated(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable()
    val sections = sectionTable.getSectionEntries().asScala
    for(section <- sections) {
      val relocEntry = section.getEntry(SectionTableEntryKey.POINTER_TO_RELOCATIONS)
      val nrRelocEntry = section.getEntry(SectionTableEntryKey.NUMBER_OF_RELOCATIONS)
      val pointerReloc = relocEntry.value
      val nrOfReloc = nrRelocEntry.value
      if(pointerReloc != 0) {
        val description = "Section Table: Pointer to Relocations is deprecated, but has value " + pointerReloc
        anomalyList += DeprecatedAnomaly(relocEntry, description)
      }
      if(nrOfReloc != 0) {
        val description = "Section Table: Number of Relocations is deprecated, but has value " + nrOfReloc
        anomalyList += DeprecatedAnomaly(nrRelocEntry, description)
      }
    }
    anomalyList.toList
  }
  
  private def checkFileAlignmentConstrains(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val fileAlignment = data.getOptionalHeader().get(WindowsEntryKey.FILE_ALIGNMENT)
    val sectionTable = data.getSectionTable()
    val sections = sectionTable.getSectionEntries().asScala
    for(section <- sections) {
      val sizeEntry = section.getEntry(SectionTableEntryKey.SIZE_OF_RAW_DATA)
      val sizeOfRaw = sizeEntry.value
      val pointerEntry = section.getEntry(SectionTableEntryKey.POINTER_TO_RAW_DATA)
      val pointerToRaw = pointerEntry.value
      if(sizeOfRaw % fileAlignment != 0) {
        val description = s"Section Table: Size of Raw Data (${sizeOfRaw}) must be a multipe of File Alignment (${fileAlignment})"
        anomalyList += WrongValueAnomaly(sizeEntry, description)
      }
      if(pointerToRaw % fileAlignment != 0) {
        val description = s"Section Table: Pointer to Raw Data (${pointerToRaw}) must be a multipe of File Alignment (${fileAlignment})"
        anomalyList += WrongValueAnomaly(pointerEntry, description)
      }  
    }
    anomalyList.toList
  }
}