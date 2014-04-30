package com.github.katjahahn.tools.anomalies

import scala.collection.mutable.ListBuffer

trait SectionTableScanning extends AnomalyScanner {

  //TODO ascending order of VAs
  //multiple of FileAlignment SIZE_OF_RAW_DATA (for executable images only) and zero if only unitialized data
  //multiple of FileAlignment POINTER_TO_RAW_DATA  and zero if only uninitialized data
  //POINTER_TO_RELOC, NumberOfRelocations zero for executables
  //PointerToLinenumbers, NumberOfLinenumbers zero for images (COFF debugging deprecated)
  //Reserved section characteristic flags
  
  abstract override def scan(): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    super.scan ::: anomalyList.toList
  }
}