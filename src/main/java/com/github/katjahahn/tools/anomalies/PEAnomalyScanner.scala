package com.github.katjahahn.tools.anomalies

import java.io.File
import com.github.katjahahn.PEData
import com.github.katjahahn.PELoader
import PartialFunction._
import com.github.katjahahn.IOUtil._
import scala.collection.JavaConverters._

class PEAnomalyScanner(data: PEData) extends AnomalyScanner(data) {

  /**
   * Scans the PE and returns a report of the anomalies found.
   *
   * @return a description string of the scan
   */
  override def scanReport: String = {
    val report = StringBuilder.newBuilder
    report ++= "Scanned File: " + data.getFile.getName + NL
    for (anomaly <- scan()) {
      report ++= "\t* " + anomaly.description + NL
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

  def getAnomalies: java.util.List[Anomaly] = scan.asJava

}

object PEAnomalyScanner {

  /**
   * Parses the given file and creates a PEAnomalyScanner instance that has all scanning
   *  characteristics applied.
   *
   * @param file the pe file to scan for
   * @return a PEAnomalyScanner instance with the traits applied from the boolean values
   */
  def getInstance(file: File): PEAnomalyScanner = {
    val data = PELoader.loadPE(file)
    getInstance(data)
  }

  /**
   * Creates a PEAnomalyScanner instance that has all scanning characteristics
   * applied.
   *
   * @param data the PEData object created by the PELoader
   * @return a PEAnomalyScanner instance with the traits applied from the boolean values
   */
  def getInstance(data: PEData): PEAnomalyScanner =
    new PEAnomalyScanner(data) with COFFHeaderScanning with 
    OptionalHeaderScanning with SectionTableScanning with MSDOSHeaderScanning

  //TODO add DOS stub anomaly scanning
  def main(args: Array[String]): Unit = {
    var counter = 0
    //    val files = new File("src/main/resources/x64viruses/").listFiles
    //    for (file <- files) {
    val file = new File("src/main/resources/unusualfiles/tinype/tinyest.exe")
    val data = PELoader.loadPE(file)
    println(data) //TODO parse section table of tinyest.exe correctly! Recognize collapsed MSDOS Header!
    val scanner = new PEAnomalyScanner(data) with SectionTableScanning with OptionalHeaderScanning with COFFHeaderScanning
    println(scanner.scanReport)
    //      val report = scanner.scanReport
    //      if(!report.isEmpty()) {
    //    	  println(report)
    //      }
    //      val list = scanner.scan
    //      if (list.size > 0 && !list.forall(_.isInstanceOf[NonDefaultAnomaly])) {
    //        println("Scanned File: " + data.getFile.getName)
    //        counter += 1
    //        list.foreach(a => println("\t*" + a))
    //        println()
    //      }
    //    }
    //    println("Anomalies found in " + counter + " of " + files.size + " files. (Non-Default Anomalies omitted)")
  }

}