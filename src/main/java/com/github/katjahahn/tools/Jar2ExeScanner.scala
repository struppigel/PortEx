package com.github.katjahahn.tools

import java.io.File
import java.io.RandomAccessFile
import scala.collection.mutable.ListBuffer
import java.io.FileOutputStream
import com.github.katjahahn.tools.SignatureScanner._

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
  lazy val scanResult: List[ScanResult] = scanner._scanAll(file, false).sortWith(_._1.name < _._1.name)

  private val description = Map("[Jar Manifest]" -> "Jar manifest found (PE contains unobfuscated jar)",
    "[PKZIP Archive File]" -> "Possible beginning of Jar or ZIP file found (weak indication, you may try to dump jar here)",
    "[java.exe]" -> "Call to java.exe (strong indication for Java wrapper)",
    "[javaw.exe]" -> "Call to javaw.exe (strong indication for Java wrapper)",
    "[Jar2Exe Products]" -> "File was created by Jar2Exe.com, signature found at")

  /**
   * Creates a scan report based on the signatures found.
   *
   * @return scan report
   */
  def createReport(): String = {
    if (scanResult.length == 0) return "no indication for java wrapper found"

    var lastName = ""

    (for ((sig, addr) <- scanResult) yield {
      var str = new StringBuilder()
      if (lastName != sig.name) {
        str ++= description.getOrElse(sig.name, sig.name) + "\n"
      }
      str ++= "\t\t" + addr.toString
      lastName = sig.name
      str
    }).mkString("\n")
  }

  /**
   * @return a list of addresses that might be the beginning of an embedded jar
   */
  def getPossibleJarAddresses(): List[Address] =
    for ((sig, addr) <- scanResult; if sig.name == "[PKZIP Archive File]") yield addr

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
    val scanner = new Jar2ExeScanner(new File("Minecraft.exe"))
    println(scanner.createReport)
    println("possible jar addresses")
    println(scanner.getPossibleJarAddresses)
  }
}