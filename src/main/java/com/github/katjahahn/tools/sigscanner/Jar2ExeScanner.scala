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
package com.github.katjahahn.tools.sigscanner

import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.util.zip.ZipInputStream
import java.nio.channels.Channels
import scala.collection.mutable.ListBuffer
import java.io.FileNotFoundException
import java.io.EOFException
import scala.collection.JavaConverters._
import SignatureScanner._
import java.util.Comparator

/**
 * A scanner for Wrappers of Jar to Exe converters. The class provides methods for
 * finding indicators about the tools used to wrap the jar, finding possible locations
 * of the embedded jar file and may assist in dumping it.
 *
 * @author Katja Hahn
 * @constructor Creates a Scanner instance that operates on the given file
 * @param file the file to scan or dump from
 */
class Jar2ExeScanner(file: File) {

  private lazy val scanner = new SignatureScanner(_loadSignatures(new File("javawrapperdb")))

  /**
   * A list containing the signatures and addresses where they where found.
   */
  lazy val scanResult: List[ScanResult] = scanner._findAllEPFalseMatches(file).sortWith(_._1.name < _._1.name)

  /**
   * Returns a list with all signature scan result data found in the file.
   *
   * @return list with jar related signatures found in the file
   */
  def scan(): java.util.List[MatchedSignature] = scanResult.map(SignatureScanner.toMatchedSignature).asJava

  private val description = Map("[Jar Manifest]" -> "Jar manifest (strong indication for embedded jar)",
    "[PKZIP Archive File]" -> "PZIP Magic Number (weak indication for embedded zip)",
    "[java.exe]" -> "Call to java.exe (strong indication for java wrapper)",
    "[javaw.exe]" -> "Call to javaw.exe (strong indication for java wrapper)",
    "[Jar2Exe Products]" -> "Jar2Exe.com signature",
    "[JSmooth]" -> "JSmooth signature",
    "[Launch4j]" -> "Launch4j signature",
    "[Exe4j]" -> "Exe4j signature, search in your temp folder for e4jxxxx.tmp file while application is running",
    "[CAFEBABE]" -> ".class file signature(s) found")

  def readZipEntriesAt(pos: Long): java.util.List[String] =
    _readZipEntriesAt(pos).asJava

  def _readZipEntriesAt(pos: Long): List[String] = {
    val raf = new RandomAccessFile(file, "r")
    val is = Channels.newInputStream(raf.getChannel().position(pos))
    val zis = new ZipInputStream(is)
    var entries = new ListBuffer[String]()
    try {
      var e = zis.getNextEntry()
      while (e != null) {
        entries += e.getName()
        e = zis.getNextEntry()
      }
    } finally {
      zis.close();
    }
    entries.toList
  }

  /**
   * Creates a scan report based on the signatures found.
   *
   * @return scan report
   */
  def createReport(): String = {
    if (scanResult.length == 0) return "no indication for java wrapper found"

    val ep = "Entry point: 0x" + scanner.getEntryPoint(file).toHexString + "\n\n"
    var lastName = ""
    val sigs = (for ((sig, addr) <- scanResult) yield {
      var str = new StringBuilder()
      if (lastName != sig.name) {
        str ++= "\t* " + description.getOrElse(sig.name, sig.name) + "\n"
      }
      lastName = sig.name
      str
    }).mkString

    val zipAddr = _getZipAddresses().map("0x" + _.toHexString)
    val classAddr = _getPossibleClassAddresses.map("0x" + _.toHexString)

    val addresses = if (scanResult.contains("[CAFEBABE]")) {
      ".class offsets: " + classAddr.mkString(", ") + "\n"
    } else if (zipAddr.length > 0) {
      "ZIP/Jar offsets: " + zipAddr.mkString(", ") + "\n"
    } else ""

    "Signatures found:\n" + sigs + "\n" + ep + addresses
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

  private def _getZipAddresses(): List[Address] = {
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
  private def getPossibleZipAddresses(): List[Address] =
    for ((sig, addr) <- scanResult; if sig.name == "[PKZIP Archive File]") yield addr

  /**
   * Returns offsets of the file where the 0xCAFEBABE magic number for Java .class
   * files was found. You may try to dump these files.
   *
   * @return a list of addresses that might be the beginning of an embedded jar
   */
  def getPossibleClassAddresses(): java.util.List[java.lang.Long] =
    _getPossibleClassAddresses.map(java.lang.Long.valueOf(_)).asJava

  private def _getPossibleClassAddresses(): List[Address] =
    for ((sig, addr) <- scanResult; if sig.name == "[CAFEBABE]") yield addr

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

  private def using[A <: { def close(): Unit }, B](param: A)(f: A => B): B =
    try { f(param) } finally { param.close() }

}

object Jar2ExeScanner {

  private val version = """version: 0.1
    |author: Katja Hahn
    |last update: 6.Feb 2014""".stripMargin

  private val title = "jwscan v0.1 -- by deque"

  private val usage = """Usage: java -jar jwscan.jar [-d <hexoffset>] <PEfile>
    """.stripMargin

  private type OptionMap = scala.collection.mutable.Map[Symbol, String]

  def main(args: Array[String]): Unit = {
    invokeCLI(args)
  }

  private def invokeCLI(args: Array[String]): Unit = {
    val options = nextOption(scala.collection.mutable.Map(), args.toList)
    println(title + "\n")
    if (args.length == 0 || !options.contains('inputfile)) {
      println(usage)
    } else {
      try {
        println("scanning file ...\n")
        var file = new File(options('inputfile))
        println("file name: " + file + "\n")

        if (options.contains('version)) {
          println(version)
        }

        val scanner = new Jar2ExeScanner(file)
        println(scanner.createReport())

        if (options.contains('dump)) {
          dumpFile(options, scanner)
        }
      } catch {
        case e: FileNotFoundException => System.err.println(e.getMessage())
        case e: EOFException => System.err.println("given file is no PE file")
      }
    }
  }

  private def nextOption(map: OptionMap, list: List[String]): OptionMap = {
    list match {
      case Nil => map
      case "-d" :: value :: tail =>
        nextOption(map += ('dump -> value), tail)
      case "-v" :: tail =>
        nextOption(map += ('version -> ""), tail)
      case value :: Nil => nextOption(map += ('inputfile -> value), list.tail)
      case option :: tail =>
        println("Unknown option " + option + "\n" + usage)
        sys.exit(1)
    }
  }

  private def dumpFile(options: OptionMap, scanner: Jar2ExeScanner): Unit = {
    try {
      var dumped = new File("dumped.out")
      var hexoffset = options('dump)
      if (hexoffset.startsWith("0x")) {
        hexoffset = hexoffset.drop(2)
      }
      val addr = Integer.valueOf(hexoffset, 16)
      scanner.dumpAt(addr.toInt, dumped)
      println("successfully dumped from offset 0x" + hexoffset + " to " + dumped)
    } catch {
      case e: NumberFormatException => System.err.println("no valid offset")
    }
  }
}
