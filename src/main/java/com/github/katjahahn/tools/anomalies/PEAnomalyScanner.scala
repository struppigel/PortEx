package com.github.katjahahn.tools.anomalies

import java.io.File
import com.github.katjahahn.PEData
import com.github.katjahahn.PELoader

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
    new PEAnomalyScanner(data) with OptionalHeaderScanning
  }

  def main(args: Array[String]): Unit = {
    for(file <- new File("src/main/resources/x64viruses/").listFiles) {
      val scanner = PEAnomalyScanner(file)
      val list = scanner.scan
      if(list.size > 0) {
    	  println("scanning file: " + file.getName())
    	  list.foreach(println)
    	  println()
      }
    }
  }

}