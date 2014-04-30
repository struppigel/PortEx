package com.github.katjahahn.tools.anomalies

import java.io.File
import com.github.katjahahn.PEData
import com.github.katjahahn.PELoader
import PartialFunction._
import com.github.katjahahn.IOUtil._

class PEAnomalyScanner(data: PEData) extends AnomalyScanner(data) {
  
  /**
   * Scans the PE and returns a report of the anomalies found.
   * 
   * @return a description string of the scan
   */
  override def scanReport: String = {
    val report = StringBuilder.newBuilder
    report ++= "Scanned File: " + data.getFile.getName
    for(anomaly <- scan()) {
      report ++= "\t*" + anomaly.description + NL
    }
    report.toString
  }

  /**
   * Scans the PE and returns a list of the anomalies found.
   * Returns an empty list if no traits have been added.
   * 
   * @return list of anomalies found
   */
  override def scan: List[Anomaly] = {
    List[Anomaly]()
  }

}

object PEAnomalyScanner {

  /**
   * Parses the given file and creates a PEAnomalyScanner instance that has the 
   * scanning characteristics applied defined by the boolean scanning parameters.
   * 
   * @param file the pe file to scan for
   * @param coffScanning adds COFF File Header scanning iff true
   * @param optScanning adds Optional Header scanning iff true
   * @param sectionTableScanning adds SectionTableScanning iff true
   * @return a PEAnomalyScanner instance with the traits applied from the boolean values
   */
  def getInstance(file: File, coffScanning: Boolean, optScanning: Boolean, sectionTableScanning: Boolean): PEAnomalyScanner = {
    val data = PELoader.loadPE(file)
    getInstance(data, coffScanning, optScanning, sectionTableScanning)
  }
  
  /**
   * Creates a PEAnomalyScanner instance that has the scanning characteristics 
   * applied defined by the boolean scanning parameters.
   * 
   * @param data the PEData object created by the PELoader
   * @param coffScanning adds COFF File Header scanning iff true
   * @param optScanning adds Optional Header scanning iff true
   * @param sectionTableScanning adds SectionTableScanning iff true
   * @return a PEAnomalyScanner instance with the traits applied from the boolean values
   */
  def getInstance(data: PEData, coffScanning: Boolean, optScanning: Boolean, sectionTableScanning: Boolean): PEAnomalyScanner = {
    val scanner = new PEAnomalyScanner(data) with SectionTableScanning
    
    //This is silly, but there is no choice as Scala doesn't allow dynamic mixins
    /*three traits*/
    if (coffScanning && optScanning && sectionTableScanning) {
      new PEAnomalyScanner(data) with COFFHeaderScanning with OptionalHeaderScanning with SectionTableScanning
    } 
    
    /*two traits*/ 
    else if (coffScanning && optScanning) {
      new PEAnomalyScanner(data) with COFFHeaderScanning with OptionalHeaderScanning
    } else if (coffScanning && sectionTableScanning) {
      new PEAnomalyScanner(data) with COFFHeaderScanning with SectionTableScanning
    } else if (optScanning && sectionTableScanning) {
      new PEAnomalyScanner(data) with OptionalHeaderScanning with SectionTableScanning
    } 
    
    /*one trait*/ 
    else if (coffScanning) {
      new PEAnomalyScanner(data) with COFFHeaderScanning
    } else if (optScanning) {
      new PEAnomalyScanner(data) with OptionalHeaderScanning
    } else if (sectionTableScanning) {
      new PEAnomalyScanner(data) with SectionTableScanning
    } 
    
    /*no traits*/ 
    else {
      new PEAnomalyScanner(data)
    }
  }

  //TODO VirusShare_baed21297974b6adf3298585baa78691 is very weird
  def main(args: Array[String]): Unit = {
    var counter = 0
    val files = new File("src/main/resources/x64viruses/").listFiles
    for (file <- files) {
      val data = PELoader.loadPE(file)
      val scanner = new PEAnomalyScanner(data) with SectionTableScanning with OptionalHeaderScanning with COFFHeaderScanning
//      val report = scanner.scanReport
//      if(!report.isEmpty()) {
//    	  println(report)
//      }
      val list = scanner.scan
      if (list.size > 0 && !list.forall(_.isInstanceOf[NonDefaultAnomaly])) {
        println("Scanned File: " + data.getFile.getName)
        counter += 1
        list.foreach(a => println("\t*" + a))
        println()
      }
    }
    println("Anomalies found in " + counter + " of " + files.size + " files. (Non-Default Anomalies omitted)")
  }

}