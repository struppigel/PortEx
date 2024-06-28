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
    val sigResults = new SignatureScanner(overlaySigs)._scanAt(data.getFile, overlay.getOffset) ::: FileTypeScanner(data.getFile)._scanAt(overlay.getOffset)
    for(sig <- sigResults) {
      val sigName = sig._1.name
      val description = "Overlay has signature " + sigName
      val overlayAnomaly = OverlayAnomaly(overlay, description, AnomalySubType.OVERLAY_HAS_SIGNATURE)
      anomalyList += overlayAnomaly
      if (sigName contains "zlib archive") anomalyList ++= checkPyInstaller()
    }
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
          return List(GenericReHintAnomaly("'PyInstaller archive' string in .rdata"))
        }
      }
    }
    Nil
  }

}
