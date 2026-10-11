package io.github.struppigel.tools.anomalies

import scala.collection.mutable.ListBuffer
import io.github.struppigel.parser.IOUtil._
import io.github.struppigel.tools.Overlay
import scala.collection.JavaConverters._
import io.github.struppigel.tools.sigscanner.LocationKind

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
    val sigResults = data.getSignatureMatches(LocationKind.OVERLAY).asScala
    for(sig <- sigResults) {
      val sigName = sig.getName
      val description = "Overlay has signature " + sigName
      val overlayAnomaly = OverlayAnomaly(overlay, description, AnomalySubType.OVERLAY_HAS_SIGNATURE)
      anomalyList += overlayAnomaly
      if (sigName contains "zlib archive") anomalyList ++= checkPyInstaller()
    }
    anomalyList.toList
  }

  private def checkPyInstaller(): List[Anomaly] = {
    // the signature searches the first 0x1500 bytes of .rdata, see installers.sig
    val found = data.getSignatureMatches(LocationKind.SECTION).asScala.exists(_.getName == "PyInstaller archive string")
    if (found) List(GenericReHintAnomaly("'PyInstaller archive' string in .rdata"))
    else Nil
  }

}
