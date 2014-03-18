package com.github.katjahahn.tools

import java.io.File
import java.io.ByteArrayInputStream
import java.io.BufferedInputStream
import java.io.FileInputStream
import scala.collection.mutable.ListBuffer

object StringReader {

  def main(args: Array[String]): Unit = {
    println(readStrings(new File("BinaryCollection/Chapter_3L/Lab03-01.exe"), 4))
  }

  def readStrings(file: File, minLength: Int): String = {
    val bis = new BufferedInputStream(new FileInputStream(file))
    val stream = Stream.continually(bis.read).takeWhile(_ != -1).map(_.toByte)
    (bytesToASCIIStrings(stream, minLength) ::: bytesToUTFStrings(stream, minLength)).mkString("\n")
  }

  def bytesToASCIIStrings(bytes: Stream[Byte], minLength: Int): List[String] = {
    def isASCIIPrintable(ch: Byte) = ch.toInt >= 32 && ch.toInt < 127
    var list = ListBuffer.empty[String]
    var stream = bytes
    while (!stream.isEmpty) {
      stream = stream.dropWhile(!isASCIIPrintable(_))
      val el = stream.takeWhile(isASCIIPrintable).map(_.toChar).mkString("");
      if (el.length() >= minLength) {
        list += el
      }
      stream = stream.dropWhile(isASCIIPrintable)
    }
    list.toList
  }

  def bytesToUTFStrings(bytes: Stream[Byte], minLength: Int): List[String] = {
    def isPrintable(ch: Int): Boolean = ch >= 32 && ch < 127
    var list = ListBuffer.empty[String]
    var buffer = ListBuffer.empty[Char]
    for (i <- 0 until (bytes.length >> 1)) {
      val bpos = i << 1
      val c = (((bytes(bpos) & 0x00FF) << 8) + (bytes(bpos + 1) & 0x00FF))
      if (c == '\0') {
        if (buffer.mkString("").trim().length > minLength) {
          list += buffer.mkString("").trim()
        } 
        buffer = ListBuffer.empty[Char]
      } else if(isPrintable(c)) {
        buffer += c.toChar
      }
    }
    return list.toList
  }
}