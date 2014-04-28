package com.github.katjahahn.tools.anomalies

import java.io.File
import com.github.katjahahn.PEData
import com.github.katjahahn.PELoader

class PEAnomalyScanner(data: PEData) extends AnomalyScanner(data) {

  override def scanReport(): String = {
    "scan report not implemented"
  }
  
  override def scan(): List[Anomaly] = {
	List(new Anomaly("success"))
  }
  
}

object PEAnomalyScanner {
  
  def apply(file: File): PEAnomalyScanner = {
    val data = PELoader.loadPE(file)
    new PEAnomalyScanner(data) with DeprecatedCOFFScanning
  }

  def main(args: Array[String]): Unit = {
    val file = new File("src/main/resources/x64viruses/VirusShare_fdbde2e1fb4d183cee684e7b9819bc13")
    val scanner = PEAnomalyScanner(file)
    scanner.scan.foreach(println)
  }

}