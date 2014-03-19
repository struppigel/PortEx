package com.github.katjahahn.tools

import java.io.File
import java.io.ByteArrayInputStream
import java.io.BufferedInputStream
import java.io.FileInputStream
import scala.collection.mutable.ListBuffer
import scala.collection.JavaConverters._

/**
 * @author Katja Hahn
 * 
 * <pre>
 * {@code
 * readStrings(new File("path"), 3);
 * }
 * </pre>
 */
object StringReader {

  def main(args: Array[String]): Unit = {
    println(readStrings(new File("BinaryCollection/Chapter_3L/Lab03-01.exe"), 4).asScala.mkString("\n"))
  }

  /**
   * Reads all 2-byte (Unicode) and 1-byte (ASCII) based character-strings 
   * contained in the file. Only printable ASCII characters are determined as string.
   * 
   * @param file the file that is to be searched for strings
   * @param minLength the minimum length the strings shall have
   * @return List containing the Strings found
   */
  def readStrings(file: File, minLength: Int): java.util.List[String] = {
    val bis = new BufferedInputStream(new FileInputStream(file))
    val stream = Stream.continually(bis.read).takeWhile(_ != -1).map(_.toByte)
    (bytesToASCIIStrings(stream, minLength) ::: bytesToUnicodeStrings(stream, minLength)).asJava
  }

  /**
   * Extracts all ASCII strings found in the stream.
   * 
   * @param bytes the byte stream
   * @param minLength the minimum number of characters for a string
   * @return List of the strings found in the byte stream
   */
  private def bytesToASCIIStrings(bytes: Stream[Byte], minLength: Int): List[String] = {
    def isASCIIPrintable(ch: Byte) = ch.toInt >= 32 && ch.toInt < 127
    val list = ListBuffer.empty[String]
    var stream = bytes
    while (!stream.isEmpty) {
      stream = stream.dropWhile(!isASCIIPrintable(_))
      val el = stream.takeWhile(isASCIIPrintable).map(_.toChar).mkString("");
      stream = stream.dropWhile(isASCIIPrintable)
      if (el.length() >= minLength && stream.iterator.next.toInt == 0) {
        list += el
      }
    }
    list.toList
  }

  /**
   * Extracts all Unicode strings found in the stream.
   * 
   * @param bytes the byte stream
   * @param minLength the minimum number of characters for a string
   * @return List of the strings found in the byte stream
   */
  //TODO this is slow!
  private def bytesToUnicodeStrings(bytes: Stream[Byte], minLength: Int): List[String] = {
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