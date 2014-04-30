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
  //Reserved and deprecated section characteristic flags
  
  abstract override def scan(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    anomalyList ++= checkFileAlignmentConstrains
    anomalyList ++= checkZeroValues
    anomalyList ++= checkDeprecated 
    super.scan ::: anomalyList.toList
  }
  
   private def checkDeprecated(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable
    val sections = sectionTable.getSectionEntries.asScala
    for(section <- sections) {
      val ptrLineNrEntry = section.getEntry(SectionTableEntryKey.POINTER_TO_LINE_NUMBERS)
      val lineNrEntry = section.getEntry(SectionTableEntryKey.NUMBER_OF_LINE_NUMBERS)
      val pointerLines = ptrLineNrEntry.value
      val lineNr = lineNrEntry.value
      val sectionName = section.getName
      if(pointerLines != 0) {
        val description = s"Section Table Entry ${sectionName}: Pointer to Line Numbers is deprecated, but has value " + pointerLines
        anomalyList += DeprecatedAnomaly(ptrLineNrEntry, description)
      }
      if(lineNr != 0) {
        val description = s"Section Table Entry ${sectionName}: Number of Line Numbers is deprecated, but has value " + lineNr
        anomalyList += DeprecatedAnomaly(lineNrEntry, description)
      }
    }
    anomalyList.toList
  }
  
  private def checkZeroValues(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val sectionTable = data.getSectionTable()
    val sections = sectionTable.getSectionEntries().asScala
    for(section <- sections) {
      val relocEntry = section.getEntry(SectionTableEntryKey.POINTER_TO_RELOCATIONS)
      val nrRelocEntry = section.getEntry(SectionTableEntryKey.NUMBER_OF_RELOCATIONS)
      val pointerReloc = relocEntry.value
      val nrOfReloc = nrRelocEntry.value
      val sectionName = section.getName
      if(pointerReloc != 0) {
        val description = s"Section Table Entry ${sectionName}: Pointer to Relocations should be 0 for executables, but has value " + pointerReloc
        anomalyList += DeprecatedAnomaly(relocEntry, description)
      }
      if(nrOfReloc != 0) {
        val description = s"Section Table Entry ${sectionName}: Number of Relocations should be 0 for executables, but has value " + nrOfReloc
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
      val sectionName = section.getName
      if(sizeOfRaw % fileAlignment != 0) {
        val description = s"Section Table Entry ${sectionName}: Size of Raw Data (${sizeOfRaw}) must be a multiple of File Alignment (${fileAlignment})"
        anomalyList += WrongValueAnomaly(sizeEntry, description)
      }
      if(pointerToRaw % fileAlignment != 0) {
        val description = s"Section Table Entry ${sectionName}: Pointer to Raw Data (${pointerToRaw}) must be a multiple of File Alignment (${fileAlignment})"
        anomalyList += WrongValueAnomaly(pointerEntry, description)
      }  
    }
    anomalyList.toList
  }
}