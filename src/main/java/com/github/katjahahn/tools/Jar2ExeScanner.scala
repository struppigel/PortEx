package com.github.katjahahn.tools

import java.io.File
import java.io.RandomAccessFile
import scala.collection.mutable.ListBuffer
import java.io.FileOutputStream
import com.github.katjahahn.tools.SignatureScanner._

class Jar2ExeScanner(file: File) {

  private val scanner = new SignatureScanner(_loadSignatures(new File("javawrapperdb")))
  
  def scan(): List[String] = {
    scanner.scanAll(file, false)
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

}

object Jar2ExeScanner {

  def main(args: Array[String]): Unit = {
    val scanner = new Jar2ExeScanner(new File("Minecraft.exe"))
    val list = scanner.scan()
    list.foreach(println)
  }
}