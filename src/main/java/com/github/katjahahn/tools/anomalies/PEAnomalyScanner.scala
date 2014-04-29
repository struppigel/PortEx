package com.github.katjahahn.tools.anomalies

import java.io.File
import com.github.katjahahn.PEData
import com.github.katjahahn.PELoader
import PartialFunction._

class PEAnomalyScanner(data: PEData) extends AnomalyScanner(data) {

  override def scanReport(): String = {
    "scan report not implemented"
  }

  override def scan(): List[Anomaly] = {
    List[Anomaly]()
  }

}

object PEAnomalyScanner {

  def apply(file: File): PEAnomalyScanner = {
    val data = PELoader.loadPE(file)
    new PEAnomalyScanner(data) with COFFHeaderScanning
  }

  def main(args: Array[String]): Unit = {
    var counter = 0
    val files = new File("src/main/resources/x64viruses/").listFiles
    for (file <- files) {
      val scanner = PEAnomalyScanner(file)
      val list = scanner.scan
      if (list.size > 0 && !list.forall(_.isInstanceOf[NonDefaultAnomaly])) {
        counter += 1
        println("scanning file: " + file.getName())
        list.foreach(println)
        println()
      }
    }
    println("Anomalies found in " + counter + " of " + files.size + " files. (Non-Default Anomalies omitted)")
  }

}