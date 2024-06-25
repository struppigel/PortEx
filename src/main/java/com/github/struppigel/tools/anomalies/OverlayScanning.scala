package com.github.struppigel.tools.anomalies

import scala.collection.mutable.ListBuffer
import com.github.struppigel.parser.IOUtil._
import com.github.struppigel.tools.Overlay
import com.github.struppigel.tools.sigscanner.{FileTypeScanner, Signature, SignatureScanner}

trait OverlayScanning extends AnomalyScanner {

  abstract override def scanReport(): String =
    "Applied Overlay Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val overlay = new Overlay(data.getFile)
    val anomalyList = ListBuffer[Anomaly]()
    if (overlay.exists()) {
      anomalyList ++= overlaySignatureScan(overlay)
    }
    super.scan ::: anomalyList.toList
  }

  private def overlaySignatureScan(overlay: Overlay): List[Anomaly] = {
    val anomalyList = ListBuffer[Anomaly]()
    val overlaySigs = SignatureScanner._loadOverlaySigs()
    val sigResults = new SignatureScanner(overlaySigs)._scanAt(data.getFile, overlay.getOffset)

    // adds one anomaly to the list if the filter string is found in the signature names
    def addAnomalyIfFilter(filterString : String, anomalySubType: AnomalySubType): Boolean = {
      val sigs = sigResults filter (_._1.name.toLowerCase() contains filterString.toLowerCase())
      if (sigs.nonEmpty) {
        val sigName = sigs.head._1.name
        val description = "Overlay signature " + sigName
        anomalyList += OverlayAnomaly(overlay, description, anomalySubType)
        if(sigName contains "zlib archive") {
          anomalyList ++= checkPyInstaller()
        }
        return true
      }
      false
    }

    // adds one anomaly to the list if any filter string is found in the signature names
    def addAnomalyForAnyFilter(filterStringList : List[String], anomalySubType: AnomalySubType): Unit = {
      filterStringList.takeWhile(addAnomalyIfFilter(_, anomalySubType))
    }
    addAnomalyIfFilter("installer", AnomalySubType.INSTALLER_RE_HINT )
    addAnomalyIfFilter("archive", AnomalySubType.ARCHIVE_RE_HINT)
    addAnomalyIfFilter("executable", AnomalySubType.EMBEDDED_EXE_RE_HINT)
    addAnomalyForAnyFilter(List("sfx", "self-extract"), AnomalySubType.SFX_RE_HINT)
    addAnomalyIfFilter("NSIS", AnomalySubType.NULLSOFT_RE_HINT)
    anomalyList.toList
  }

  private def checkPyInstaller(): List[Anomaly] = {
    val maxScanSize = 0x1500
    val pattern : Array[Option[Byte]] = "PyInstaller archive".getBytes.map(Some(_))
    val signature = new Signature("PyInstaller", false , pattern )
    val maybeRdata = data.getSectionTable.getSectionHeaderByName(".rdata")
    if(maybeRdata.isPresent) {
      val rdata = maybeRdata.get()
      val offset = rdata.getAlignedPointerToRaw(false)
      val size = Math.min(maxScanSize, rdata.getAlignedSizeOfRaw(false))
      val end = offset + Math.min(data.getFile.length(), size)
      for(i <- offset until end) {
        val results = new SignatureScanner(List(signature)).scanAt(data.getFile, i)
        if (!results.isEmpty) {
          return List(ComplexReHintAnomaly("zlib signature in overlay and 'PyInstaller archive' string in .rdata", AnomalySubType.PYINSTALLER_RE_HINT))
        }
      }
    }
    Nil
  }

}
