package com.github.katjahahn.tools.anomalies

import scala.collection.mutable.ListBuffer
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.SectionHeader
import com.github.katjahahn.parser.optheader.DataDirectoryKey
import com.github.katjahahn.parser.Location
import com.github.katjahahn.parser.sections.edata.ExportSection

trait ExportSectionScanning extends AnomalyScanner {
  
    abstract override def scanReport(): String =
    "Applied Export Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val maybeEdata = new SectionLoader(data).maybeLoadExportSection()
    if (maybeEdata.isPresent()) {
      val edata = maybeEdata.get
      val anomalyList = ListBuffer[Anomaly]()
      anomalyList ++= checkFractionatedExports(edata)
      super.scan ::: anomalyList.toList
    } else super.scan ::: Nil
  }

  private def checkFractionatedExports(edata: ExportSection): List[Anomaly] = {
    val locs = edata.getPhysicalLocations.asScala
    val anomalyList = ListBuffer[Anomaly]()
    val loader = new SectionLoader(data)
    val edataHeader = loader.maybeGetSectionHeaderByOffset(edata.getOffset())
    if (edataHeader.isPresent) {
      
      def isWithinEData(loc: Location): Boolean = {
        val start = edataHeader.get().getAlignedPointerToRaw
        val end = start + loader.getReadSize(edataHeader.get)
        val locEnd = loc.from + loc.size
        //ignores falty locations (indicated by -1 or larger than file size)
        //FIXME find the cause of -1 entries!
        (loc.from >= data.getFile.length) || (loc.from == -1) || (loc.from >= start && locEnd <= end)
      }
      val fractions = locs.filter(!isWithinEData(_)).toList
      if (!fractions.isEmpty) {
        val description = s"Exports are fractionated!"
        anomalyList += StructureAnomaly(PEStructureKey.EXPORT_SECTION, description,
          AnomalySubType.FRACTIONATED_DATADIR, fractions)

      }
    }
    anomalyList.toList
  }
}