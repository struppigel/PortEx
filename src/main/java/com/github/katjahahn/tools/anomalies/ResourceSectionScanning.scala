package com.github.katjahahn.tools.anomalies

import scala.collection.mutable.ListBuffer
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.SectionHeader
import com.github.katjahahn.parser.optheader.DataDirectoryKey
import com.github.katjahahn.parser.Location
import com.github.katjahahn.parser.sections.rsrc.ResourceSection
import scala.collection.JavaConverters._

trait ResourceSectionScanning extends AnomalyScanner {
  abstract override def scanReport(): String =
    "Applied Resource Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val maybeRsrc = new SectionLoader(data).maybeLoadResourceSection()
    if (maybeRsrc.isPresent()) {
      val rsrc = maybeRsrc.get
      val anomalyList = ListBuffer[Anomaly]()
      anomalyList ++= checkFractionatedResources(rsrc)
      anomalyList ++= checkResourceLoop(rsrc)
      super.scan ::: anomalyList.toList
    } else super.scan ::: Nil
  }

  private def checkResourceLoop(rsrc: ResourceSection): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    if (rsrc.hasLoop) {
      val description = "Detected loop in resource tree!"
      //TODO specify exact location of loop?
      val locs = rsrc.getPhysicalLocations.asScala.toList 
      anomalyList += StructureAnomaly(PEStructureKey.RESOURCE_SECTION, 
          description, AnomalySubType.RESOURCE_LOOP, locs)
    }
    anomalyList.toList
  }

  private def checkFractionatedResources(rsrc: ResourceSection): List[Anomaly] = {
    val locs = rsrc.getPhysicalLocations.asScala
    val anomalyList = ListBuffer[Anomaly]()
    val loader = new SectionLoader(data)
    val rsrcHeader = loader.maybeGetSectionHeaderByOffset(rsrc.getOffset())
    if (rsrcHeader.isPresent) {

      def isWithinEData(loc: Location): Boolean = {
        val start = rsrcHeader.get().getAlignedPointerToRaw
        val end = start + loader.getReadSize(rsrcHeader.get)
        val locEnd = loc.from + loc.size
        //ignores falty locations (indicated by -1 or larger than file size)
        //FIXME find the cause of -1 entries!
        (loc.from >= data.getFile.length) || (loc.from == -1) || (loc.from >= start && locEnd <= end)
      }
      val fractions = locs.filter(!isWithinEData(_)).toList
      if (!fractions.isEmpty) {
        val description = "Resources are fractionated!"
        anomalyList += StructureAnomaly(PEStructureKey.RESOURCE_SECTION, description,
          AnomalySubType.FRACTIONATED_DATADIR, fractions)

      }
    }
    anomalyList.toList
  }
}