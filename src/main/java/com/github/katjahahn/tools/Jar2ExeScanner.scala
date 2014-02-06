package com.github.katjahahn.tools

import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.util.zip.ZipInputStream
import com.github.katjahahn.tools.SignatureScanner._
import java.nio.channels.Channels
import scala.collection.mutable.ListBuffer

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
  lazy val scanResult: List[ScanResult] = scanner.findAllEPFalseMatches(file).sortWith(_._1.name < _._1.name)

  private val description = Map("[Jar Manifest]" -> "Jar manifest (strong indication for embedded jar)",
    "[PKZIP Archive File]" -> "PZIP Magic Number (weak indication for embedded zip)",
    "[java.exe]" -> "Call to java.exe (strong indication for java wrapper)",
    "[javaw.exe]" -> "Call to javaw.exe (strong indication for java wrapper)",
    "[Jar2Exe Products]" -> "Jar2Exe.com signature",
    "[JSmooth]" -> "JSmooth signature",
    "[Launch4j]" -> "Launch4j signature",
    "[Exe4j]" -> "Exe4j signature, search in your temp folder for e4jxxxx.tmp file while application is running",
    "[CAFEBABE]" -> ".class file signature(s) found")

  def readZipEntriesAt(pos: Long): List[String] = {
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
  def createReport(verbose: Boolean = false): String = {
    if (scanResult.length == 0) return "no indication for java wrapper found"

    val ep = "Entry point: 0x" + scanner.getEntryPoint(file).toHexString + "\n\n"
    var lastName = ""
    val sigs = (for ((sig, addr) <- scanResult) yield {
      var str = new StringBuilder()
      if (lastName != sig.name) {
        str ++= "\t* " + description.getOrElse(sig.name, sig.name) + "\n"
      }
      if (verbose) str ++= "\t\t" + addr.toString + "\n"
      lastName = sig.name
      str
    }).mkString

    val zipAddr = getZipAddresses().map("0x" + _.toHexString)
    val classAddr = getPossibleClassAddresses.map("0x" + _.toHexString)

    val addresses = if (scanResult.contains("[CAFEBABE]")) {
      ".class offsets: " + classAddr.mkString(", ") + "\n\n"
    } else if (zipAddr.length > 0) {
      "ZIP/Jar offsets: " + zipAddr.mkString(", ") + "\n\n"
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
  def getZipAddresses(): List[Address] = {
    val possibleAddr = getPossibleZipAddresses()
    var entryNr = 0
    possibleAddr.filter(addr =>
      if (entryNr == 0) {
        entryNr += readZipEntriesAt(addr).length
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
  def getPossibleClassAddresses(): List[Address] =
    for ((sig, addr) <- scanResult; if sig.name == "[CAFEBABE]") yield addr

  /**
   * Dumps the part of PE file starting at the given address to the given
   * destination path.
   *
   * @param addr the address to start dumping the file from
   * @param dest the location to save the dump to
   */
  def dumpAt(addr: Long, dest: File): Unit = {
    val raf = new RandomAccessFile(file, "r")
    val out = new FileOutputStream(dest)
    try {
      raf.seek(addr)
      val buffer = Array.fill(1024)(0.toByte)
      var bytesRead = raf.read(buffer)
      while (bytesRead > 0) {
        out.write(buffer, 0, bytesRead)
        bytesRead = raf.read(buffer)
      }
    } finally {
      raf.close()
      out.close()
    }
    println("successfully dumped " + dest)
  }

}

object Jar2ExeScanner {

  def main(args: Array[String]): Unit = {
    val scanner = new Jar2ExeScanner(new File("launch4jexe.exe"))
    println(scanner.createReport())
  }
}