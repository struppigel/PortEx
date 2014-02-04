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

  private val description = Map("[Jar Manifest]" -> "Jar manifest found",
    "[PKZIP Archive File]" -> "Possible beginning of Jar or ZIP file found (weak indication, you may try to dump jar here)",
    "[java.exe]" -> "Call to java.exe (strong indication for Java wrapper)",
    "[javaw.exe]" -> "Call to javaw.exe (strong indication for Java wrapper)",
    "[Jar2Exe Products]" -> "Jar2Exe.com signature, you can dump jar if not encrypted",
    "[JSmooth]" -> "JSmooth signature, you can dump the jar",
    "[Exe4j]" -> "Exe4j signature, search in your temp folder for e4jxxxx.tmp file while application is running",
    "[CAFEBABE]" -> ".class file signature found, you can dump this .class")

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

    var lastName = ""

    (for ((sig, addr) <- scanResult) yield {
      var str = new StringBuilder()
      if (lastName != sig.name) {
        str ++= description.getOrElse(sig.name, sig.name) + "\n"
      }
      if (verbose) str ++= addr.toString + "\n"
      lastName = sig.name
      str
    }).mkString
  }

  /**
   * @return a list of addresses that might be the beginning of an embedded jar
   */
  def getPossibleJarAddresses(): List[Address] =
    for ((sig, addr) <- scanResult; if sig.name == "[PKZIP Archive File]") yield addr

  /**
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

//TODO launch4j
//determine entry nr of zip and remove these from possible starting addresses
//check of valid zip file by using readentries
//get original jar from jsmooth
object Jar2ExeScanner {

  def main(args: Array[String]): Unit = {
    val scanner = new Jar2ExeScanner(new File("minecraft.exe"))
    println(scanner.createReport())
    println("possible jar addresses")
    var addresses = scanner.getPossibleJarAddresses
    println(addresses.mkString(", "))
    println("jar entries at " + addresses(0))
    scanner.readZipEntriesAt(addresses(0)).foreach(println)
  }
}