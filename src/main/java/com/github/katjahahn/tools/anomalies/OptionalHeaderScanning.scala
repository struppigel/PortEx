package com.github.katjahahn.tools.anomalies

import scala.collection.mutable.ListBuffer
import com.github.katjahahn.optheader.OptionalHeader
import com.github.katjahahn.PEData
import com.github.katjahahn.optheader.DataDirectoryKey
import java.util.Map
import com.github.katjahahn.IOUtil

trait OptionalHeaderScanning extends AnomalyScanner {
  
  abstract override def scan(): List[Anomaly] = {
    val opt = data.getOptionalHeader()
    val anomalyList = ListBuffer[Anomaly]()
    if (opt == null) return Nil
    anomalyList ++= dataDirScan(opt)
    super.scan ::: anomalyList.toList
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