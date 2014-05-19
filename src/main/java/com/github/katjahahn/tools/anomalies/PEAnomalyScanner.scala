/**
 * *****************************************************************************
 * Copyright 2014 Katja Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ****************************************************************************
 */
package com.github.katjahahn.tools.anomalies

import java.io.File
import com.github.katjahahn.PEData
import com.github.katjahahn.PELoader
import PartialFunction._
import com.github.katjahahn.IOUtil._
import scala.collection.JavaConverters._
import com.github.katjahahn.tools.Overlay

/**
 * Scans for anomalies and malformations in a PE file.
 *
 * @author Katja Hahn
 */
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
    new PEAnomalyScanner(data) with COFFHeaderScanning with OptionalHeaderScanning with SectionTableScanning with MSDOSHeaderScanning

  def main(args: Array[String]): Unit = {
    var counter = 0
    val folder = new File("src/main/resources/x64viruses/");
    for (file <- folder.listFiles()) {
      val data = PELoader.loadPE(file)
      //    println(data) 
      val scanner = new PEAnomalyScanner(data) with SectionTableScanning with OptionalHeaderScanning with COFFHeaderScanning
      val over = new Overlay(data)
      println(scanner.scanReport)
      println("has overlay: " + over.exists())
      println("overlay offset: " + over.getOffset())
      println()
    }
  }

}
