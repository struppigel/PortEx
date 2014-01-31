package com.github.katjahahn.tools

import java.io.File
import java.io.RandomAccessFile
import scala.collection.mutable.ListBuffer
import java.io.FileOutputStream

class Jar2ExeScanner(file: File) {

  private val zipMagic = Signature("PKZIP Archive File", false, "50 4B 03 04")
  private val manifestSig = Signature("Jar Manifest", false, "4D 45 54 41 2D 49 4E 46 2F 4D 41 4E 49 46 45 53 54 2E 4D 46")

  def scan(): List[(Signature, Long)] = {
    var sigTree = SignatureTree()
    sigTree += zipMagic
    var matches = ListBuffer[(Signature, Long)]()
    using(new RandomAccessFile(file, "r")) { raf =>
      val bytes = Array.fill(manifestSig.signature.length)(0.toByte)
      for (addr <- 0L to file.length()) {
        raf.seek(addr)
        val bytesRead = raf.read(bytes)
        if (bytesRead >= manifestSig.signature.length) {
          matches ++= sigTree.findMatches(bytes.toList).map((_, addr))
        }
      }
    }
    matches.toList
  }

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

  private def using[A <: { def close(): Unit }, B](param: A)(f: A => B): B =
    try { f(param) } finally { param.close() }

}

object Jar2ExeScanner {

  def main(args: Array[String]): Unit = {
    val scanner = new Jar2ExeScanner(new File("Minecraft.exe"))
    val list = scanner.scan()
    val (sig, addr) = list(0)
    scanner.dumpAt(addr, new File("out.zip"))
  }
}