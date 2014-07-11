package com.github.katjahahn.tools.anomalies

import scala.collection.mutable.ListBuffer
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.idata.ImportSection
import com.github.katjahahn.parser.sections.SectionHeader
import com.github.katjahahn.parser.optheader.DataDirectoryKey
import com.github.katjahahn.parser.Location

trait ImportSectionScanning extends AnomalyScanner {

  abstract override def scanReport(): String =
    "Applied Import Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val maybeIdata = new SectionLoader(data).maybeLoadImportSection()
    if (maybeIdata.isPresent()) {
      val idata = maybeIdata.get
      val anomalyList = ListBuffer[Anomaly]()
      anomalyList ++= checkFractionatedImports(idata)
      anomalyList ++= checkKernel32Imports(idata)
      super.scan ::: anomalyList.toList
    } else super.scan ::: Nil
  }

  private def checkFractionatedImports(idata: ImportSection): List[Anomaly] = {
    val locs = idata.getLocations.asScala
    val anomalyList = ListBuffer[Anomaly]()
    val loader = new SectionLoader(data)
    val idataHeader = loader.maybeGetSectionHeaderByOffset(idata.getOffset())
    if (idataHeader.isPresent) {
      val idata = idataHeader.get
      
      def isWithinIData(loc: Location): Boolean = {
        val start = idata.getAlignedPointerToRaw()
        val end = start + loader.getReadSize(idata)
        val locEnd = loc.from + loc.size
        //ignores falty locations (indicated by -1 or larger than file size)
        //FIXME find the cause of -1 entries!
        (loc.from >= data.getFile.length) || (loc.from == -1) || (loc.from >= start && locEnd <= end)
      }
      def headerDescription(loc: Location): String = {
        val sec = loader.maybeGetSectionHeaderByOffset(loc.from);
        val sec2 = loader.maybeGetSectionHeaderByOffset(loc.from + loc.size)
        var description = ""
        if(sec.isPresent)
          description += " in section " + sec.get.getName
        if(sec2.isPresent && sec2 != sec)
          description += " in section " + sec2.get.getName
        if(!sec.isPresent && !sec2.isPresent)
          description += " not in any section"
        description
      }
      val fractions = locs.filter(!isWithinIData(_)).toList
      if (!fractions.isEmpty) {
        val fracDescriptions = fractions.map(f => s"(${f.from}, ${f.from + f.size})" + headerDescription(f)).mkString(", ")
        val description = s"Imports are fractionated! Import section: ${idata.getName}, fraction locations: " + fracDescriptions
        anomalyList += StructureAnomaly(PEStructureKey.IMPORT_SECTION, description,
          AnomalySubType.FRACTIONATED_DATADIR, fractions)

      }
    }
    anomalyList.toList
  }

  //TODO test
  private def checkKernel32Imports(idata: ImportSection): List[Anomaly] = {
    val imports = idata.getImports.asScala.filter(i =>
      i.getName().equalsIgnoreCase("kernel32.dll") &&
        i.getOrdinalImports().size() > 0).toList
    val anomalyList = ListBuffer[Anomaly]()
    if (!imports.isEmpty) {
      val description = "Imports from Kernel32.dll by ordinal, namely: " + imports.mkString(", ")
      anomalyList += new ImportAnomaly(imports, description, AnomalySubType.KERNEL32_BY_ORDINAL_IMPORTS,
        PEStructureKey.IMPORT_DLL)
    }
    anomalyList.toList
  }

}