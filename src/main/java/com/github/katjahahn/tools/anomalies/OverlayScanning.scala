package com.github.katjahahn.tools.anomalies

import scala.collection.mutable.ListBuffer
import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.tools.Overlay
import com.github.katjahahn.tools.sigscanner.{FileTypeScanner, SignatureScanner}

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
    def addAnomalyIfFilter(filterString : String, rawDescription: String): Boolean = {
      val sigs = sigResults filter (_._1.name.toLowerCase() contains filterString.toLowerCase())
      if (sigs.nonEmpty) {
        val sigName = sigs.head._1.name
        val description = rawDescription.replace("{signame}", sigName)
        anomalyList += OverlayAnomaly(overlay, description, AnomalySubType.OVERLAY_FILETYPE_HINT)
        return true
      }
      false
    }

    // adds one anomaly to the list if any filter string is found in the signature names
    def addAnomalyForAnyFilter(filterStringList : List[String], rawDescription : String): Unit = {
      filterStringList.takeWhile(addAnomalyIfFilter(_, rawDescription))
    }
    addAnomalyIfFilter("installer", "Overlay indicates that the file is an installer, extract the install script and contained files")
    addAnomalyIfFilter("archive", "Overlay contains an archive {signame}, dump the overlay and try to unpack it")
    addAnomalyIfFilter("executable", "Overlay contains an executable {signame}, dump the overlay and analyse the file")
    addAnomalyForAnyFilter(List("sfx", "self-extract"), "Overlay contains a self-extracting archive {signame}, try to extract the files or run the file and collect them")
    addAnomalyIfFilter("NSIS", "Overlay indicates that the file is a Nullsoft installer, extract the install script and contained files")
    anomalyList.toList
  }

}
