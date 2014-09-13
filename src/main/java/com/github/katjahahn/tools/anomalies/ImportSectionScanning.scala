package com.github.katjahahn.tools.anomalies

import scala.collection.mutable.ListBuffer
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.idata.ImportSection
import com.github.katjahahn.parser.sections.SectionHeader
import com.github.katjahahn.parser.optheader.DataDirectoryKey
import com.github.katjahahn.parser.Location
import com.github.katjahahn.parser.sections.idata.ImportDLL

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
      anomalyList ++= checkVirtualImports(idata)
      super.scan ::: anomalyList.toList
    } else super.scan ::: Nil
  }

  private def checkVirtualImports(idata: ImportSection): List[Anomaly] = {
    val fileSize = data.getFile.length
    def isVirtual(imp: ImportDLL): Boolean = {
      val locs = imp.getLocations().asScala
      locs.exists(loc => loc.from + loc.size > fileSize)
    }
    val imports = idata.getImports.asScala
    val anomalyList = ListBuffer[Anomaly]()
    for(imp <- imports) {
      if(isVirtual(imp)) {
        val description = s"Import DLL has virtual imports: ${imp.getName()}"
        anomalyList += ImportAnomaly(List(imp), description,
          AnomalySubType.VIRTUAL_IMPORTS, PEStructureKey.IMPORT_SECTION)
      }
    }
    anomalyList.toList
  }

  private def checkFractionatedImports(idata: ImportSection): List[Anomaly] = {
    val locs = idata.getPhysicalLocations.asScala
    val anomalyList = ListBuffer[Anomaly]()
    val loader = new SectionLoader(data)
    val idataHeader = loader.maybeGetSectionHeaderByOffset(idata.getOffset())
    if (idataHeader.isPresent) {

      def isWithinIData(loc: Location): Boolean = {
        val start = idataHeader.get().getAlignedPointerToRaw
        val end = start + loader.getReadSize(idataHeader.get)
        val locEnd = loc.from + loc.size
        //ignores falty locations (indicated by -1 or larger than file size)
        //FIXME find the cause of -1 entries!
        (loc.from >= data.getFile.length) || (loc.from == -1) || (loc.from >= start && locEnd <= end)
      }
      val fractions = locs.filter(!isWithinIData(_)).toList
      if (!fractions.isEmpty) {
        val affectedImports = idata.getImports.asScala.filter(i =>
          i.getLocations.asScala.filter(!isWithinIData(_)).size > 0).toList
        val description = s"Imports are fractionated! Affected import DLLs: ${affectedImports.map(_.getName()).mkString(", ")}"
        anomalyList += ImportAnomaly(affectedImports, description,
          AnomalySubType.FRACTIONATED_DATADIR, PEStructureKey.IMPORT_SECTION)

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