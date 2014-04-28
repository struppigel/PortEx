package com.github.katjahahn.tools.anomalies

import scala.collection.mutable.ListBuffer
import com.github.katjahahn.optheader.OptionalHeader
import com.github.katjahahn.PEData
import com.github.katjahahn.optheader.DataDirectoryKey
import java.util.Map
import com.github.katjahahn.IOUtil
import com.github.katjahahn.optheader.WindowsEntryKey

trait OptionalHeaderScanning extends AnomalyScanner {
  
  abstract override def scan(): List[Anomaly] = {
    val opt = data.getOptionalHeader()
    val anomalyList = ListBuffer[Anomaly]()
    if (opt == null) return Nil
    anomalyList ++= dataDirScan(opt)
    anomalyList ++= windowsFieldScan(opt)
    super.scan ::: anomalyList.toList
  }
  
  private def windowsFieldScan(opt: OptionalHeader): List[Anomaly] = {
   val anomalyList = checkImageBase(opt)
   //TODO implement
   anomalyList.toList
  }
  
  private def checkImageBase(opt: OptionalHeader): List[Anomaly] = {
    def isDLL(): Boolean = false //TODO implement
    
    val anomalyList = ListBuffer[Anomaly]()
    val entry = opt.getWindowsFieldEntry(WindowsEntryKey.IMAGE_BASE)
    val imageBase = entry.value
    if(imageBase % 65536 != 0) {
      val description = "Image Base must be a multiple of 64 K"
      anomalyList += WrongValueAnomaly(entry, description)
    }
    if(isDLL() && imageBase != 0x10000000) {
      val description = "the default image base for a DLL should be 0x10000000, but is " + java.lang.Long.toHexString(imageBase) //TODO hex
      anomalyList += NonDefaultAnomaly(entry, description)
    }
    anomalyList.toList
  }
  
  private def dataDirScan(opt: OptionalHeader): List[Anomaly] = {
    val datadirs = opt.getDataDirEntries()
    if(datadirs.containsKey(DataDirectoryKey.RESERVED)) {
      val entry = datadirs.get(DataDirectoryKey.RESERVED)
      val description = "Reserved Data Directory Entry is not 0. Entry --> " + IOUtil.NL + entry.toString
      List(ReservedAnomaly(entry, description))
    } else Nil
  }

}