/**
 * *****************************************************************************
 * Copyright 2014 Karsten Philipp Boris Hahn
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
package io.github.struppigel.tools.sigscanner

import io.github.struppigel.parser.AnalysisInterruptedException
import io.github.struppigel.parser.ScalaIOUtil.using

import java.io.{File, FileOutputStream, RandomAccessFile}
import java.nio.channels.{Channels, ClosedByInterruptException}
import java.util.zip.ZipInputStream
import scala.collection.JavaConverters.seqAsJavaListConverter
import scala.collection.mutable.ListBuffer

/**
 * A scanner for Wrappers of Jar to Exe converters. The class provides methods for
 * finding indicators about the tools used to wrap the jar, finding possible locations
 * of the embedded jar file and may assist in dumping it.
 *
 * @author Karsten Philipp Boris Hahn
 * Creates a Scanner instance that operates on the given file
 * @param file the file to scan or dump from
 */
class Jar2ExeScanner(file: File) {

  /**
   * The signatures found in the file, sorted by name.
   */
  private lazy val scanResults: IndexedSeq[SignatureMatch] =
    DefaultSignatures.javaWrapperScanner._scanFile(file).sortBy(_.getName)

  /**
   * Returns a list with all signature scan result data found in the file.
   *
   * @return list with jar related signatures found in the file
   */
  def scan(): java.util.List[SignatureMatch] = scanResults.asJava

  def readZipEntriesAt(pos: Long): java.util.List[String] =
    _readZipEntriesAt(pos).asJava

  def _readZipEntriesAt(pos: Long): List[String] = {
    val raf = new RandomAccessFile(file, "r")
    val is = Channels.newInputStream(raf.getChannel().position(pos))
    val zis = new ZipInputStream(is)
    val entries = new ListBuffer[String]()
    try {
      var e = zis.getNextEntry()
      while (e != null) {
        entries += e.getName()
        e = zis.getNextEntry()
      }
    } catch {
      // the zip is read through an interruptible channel: interruption of the
      // analysis thread must abort the scan instead of being swallowed
      case e: ClosedByInterruptException  => throw new AnalysisInterruptedException()
      case e: AnalysisInterruptedException => throw e
      case e: IllegalArgumentException => return Nil
      case e: Exception                => //System.err.println(e.getMessage())
    } finally {
      zis.close()
    }
    entries.toList
  }

  /**
   * Creates a scan report based on the signatures found.
   *
   * @return scan report
   */
  def createReport(): String = {
    if (scanResults.isEmpty) return "no indication for java wrapper found"
    val sigs = scanResults.map(_.getName).distinct.map { name =>
      val sig = scanResults.find(_.getName == name).get.getSignature
      "\t* " + sig.getDescription.orElse(name) + "\n"
    }.mkString

    val zipAddr = _getZipAddresses().map("0x" + _.toHexString)
    val classAddr = _getPossibleClassAddresses.map("0x" + _.toHexString)
    val addresses = {
      if (classAddr.nonEmpty) {
        ".class offsets: " + classAddr.mkString(", ") + "\n"
      } else ""
    } ++
      {
        if (zipAddr.nonEmpty) {
          "ZIP/Jar offsets: " + zipAddr.mkString(", ") + "\n"
        } else ""
      }

    "Signatures found:\n" + sigs + "\n" + addresses
  }

  /**
   * Determines the offset of the beginning of zip/jar archives within the file.
   *
   * It uses the PK ZIP magic number to determine possible addresses and starts to
   * read for entries there. If there is at least one entry found, the address is
   * returned.
   *
   * @return a list of addresses where a zip/jar with entries was found
   */
  def getZipAddresses(): java.util.List[java.lang.Long] = {
    _getZipAddresses().map(java.lang.Long.valueOf(_)).asJava
  }

  private def _getZipAddresses(): List[Long] = {
    val possibleAddr = getPossibleZipAddresses()
    var entryNr = 0
    possibleAddr.filter(addr =>
      if (entryNr == 0) {
        entryNr += _readZipEntriesAt(addr).length
        true
      } else {
        entryNr = entryNr - 1
        false
      })
  }

  /**
   * @return a list of addresses that might be the beginning of an embedded zip or jar
   */
  private def getPossibleZipAddresses(): List[Long] =
    scanResults.filter(_.getName == Jar2ExeScanner.ZipSignature).map(_.getOffset).toList

  /**
   * Returns offsets of the file where the 0xCAFEBABE magic number for Java .class
   * files was found. You may try to dump these files.
   *
   * @return a list of addresses that might be the beginning of an embedded jar
   */
  def getPossibleClassAddresses(): java.util.List[java.lang.Long] =
    _getPossibleClassAddresses.map(java.lang.Long.valueOf(_)).asJava

  private def _getPossibleClassAddresses(): List[Long] =
    scanResults.filter(_.getName == Jar2ExeScanner.ClassSignature).map(_.getOffset).toList

  /**
   * Dumps the part of PE file starting at the given address to the given
   * destination path.
   *
   * @param addr the address to start dumping the file from
   * @param dest the location to save the dump to
   */
  def dumpAt(addr: Long, dest: File): Unit = {
    using(new RandomAccessFile(file, "r")) { raf =>
      using(new FileOutputStream(dest)) { out =>
        raf.seek(addr)
        val buffer = Array.fill(1024)(0.toByte)
        var bytesRead = raf.read(buffer)
        while (bytesRead > 0) {
          out.write(buffer, 0, bytesRead)
          bytesRead = raf.read(buffer)
        }
      }
    }
  }

}

object Jar2ExeScanner {

  /** name of the signature for the start of zip files in javawrappers.sig */
  val ZipSignature = "PKZIP Archive File"

  /** name of the signature for the start of class files in javawrappers.sig */
  val ClassSignature = "CAFEBABE"
}
