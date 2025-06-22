/*******************************************************************************
 * Copyright 2024 Karsten Philipp Boris Hahn
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
 ******************************************************************************/
package io.github.struppigel.tools.rehints

import io.github.struppigel.parser.IOUtil._
import io.github.struppigel.parser.{PEData, PELoader}
import io.github.struppigel.tools.rehints.scanning._
import io.github.struppigel.tools.anomalies.{Anomaly, PEAnomalyScanner}
import io.github.struppigel.tools.rehints.scanning.{AHKScanning, AutoItScanning, CompressorScanning, DotNetCoreAppBundleScanning, ElectronScanning, EmbeddedFileScanning, FakeVMPScanning, InnoSetupScanning, NullsoftScanning, ProcessInjectionScanning, PyInstallerScanning, ScriptToExeScanning, Sfx7zipScanning}

import java.io.File
import scala.collection.JavaConverters._

/**
 * Scans for anomalies and malformations in a PE file.
 *
 * @author Karsten Hahn
 */
class PEReHintScanner(data: PEData, anomalies: java.util.List[Anomaly]) extends ReHintScanner(data, anomalies)
{

  /**
   * Scans the PE and returns a report of the rehints found.
   *
   * @return a description string of the scan
   */
  override def scanReport: String = {
    val report = StringBuilder.newBuilder
    report ++= "Scanned File: " + data.getFile.getName + NL
    for (rehint <- scan()) {
      report ++= rehint.toString + NL
    }
    report.toString
  }

  /**
   * Scans the PE and returns a (scala-)list of the anomalies found.
   * Returns an empty list if no traits have been added.
   *
   * Use getReHints for a Java compatible list.
   *
   * @return (scala-)list of rehints found
   */
  override def scan: List[ReHint] = Nil

  /**
   * Returns a list of rehints that were found in the PE file.
   *
   * @return list of rehints found
   */
  def getReHints: java.util.List[ReHint] = scan.asJava

}

object PEReHintScanner {

  /**
   * Parses the given file and creates a PEAnomalyScanner instance that has all scanning
   *  characteristics applied.
   *
   * @param file the pe file to scan for
   * @return a PEReHintScanner instance with the traits applied from the boolean values
   */
  def newInstance(file: File): PEReHintScanner = {
    val data = PELoader.loadPE(file)
    val anoms = new PEAnomalyScanner(data).getAnomalies
    newInstance(data, anoms)
  }

  /**
   * Creates a PEReHintScanner instance that has all scanning characteristics
   * applied.
   *
   * @param data the PEData object created by the PELoader
   * @param anomalies to avoid scanning for anomalies several times, provide the list
   * @return a PEReHintScanner instance with the traits applied from the boolean values
   */
  def newInstance(data: PEData, anomalies: java.util.List[Anomaly]): PEReHintScanner =
    new PEReHintScanner(data, anomalies)
      with AHKScanning
      with AutoItScanning
      with CompressorScanning
      with DotNetCoreAppBundleScanning
      with ElectronScanning
      with EmbeddedFileScanning
      with FakeVMPScanning
      with InnoSetupScanning
      with NullsoftScanning
      with ProcessInjectionScanning
      with PyInstallerScanning
      with ScriptToExeScanning
      with Sfx7zipScanning

  def apply(data: PEData, anomalies: java.util.List[Anomaly]): PEReHintScanner = newInstance(data, anomalies)

  def main(args: Array[String]): Unit = {
    val folder = new File("C:\\Users\\strup\\Repos\\PortEx\\portextestfiles\\testfiles\\")
    var counter = 0
    val list = List("electron.exe",
      "pyinstaller", "upx.exe", "autoit", "ahk", "batch2exe")
    for (file <- folder.listFiles() if list.contains(file.getName())) {
      try {
        val scanner = PEReHintScanner.newInstance(file)
        counter += 1
        println(file.getName())
        if(counter % 10 == 0) println("files read: " + counter)
        val rehints = scanner.getReHints.asScala
        println(scanner.scanReport)
      } catch {
        case e: Exception => e.printStackTrace()
      }
    }
  }

}
