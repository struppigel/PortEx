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
package com.github.katjahahn.tools

import com.github.katjahahn.parser.ScalaIOUtil.using
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.parser.PELoader
import java.io.RandomAccessFile
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.Reader

/**
 * @author Katja Hahn
 *
 * <pre>
 * {@code
 * readStrings(new File("path"), 3);
 * }
 * </pre>
 */
object StringExtractor {

  def main(args: Array[String]): Unit = {
    val file = new File("/home/deque/portextestfiles/MinecraftForceOp.exe")
    println(readStrings(file, 4).asScala.mkString("\n"))
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
    (_readASCIIStrings(file, minLength, Integer.MAX_VALUE, Integer.MAX_VALUE) ::: 
        _readStrings(file, minLength, Integer.MAX_VALUE, Integer.MAX_VALUE, "UTF-16LE")).asJava
  }

  /**
   * Reads all 1-byte (ASCII) based character-strings
   * contained in the file. Only printable ASCII characters are determined as string.
   *
   * @param file the file that is to be searched for strings
   * @param minLength the minimum length the strings shall have
   * @return List containing the Strings found
   */
  def readASCIIStrings(file: File, minLength: Int): java.util.List[String] = {
    _readASCIIStrings(file, minLength, Integer.MAX_VALUE, Integer.MAX_VALUE).asJava
  }

  def _readASCIIStrings(file: File, minLength: Int, maxLength: Int, maxNumber: Int, filter: String => Boolean = { _ => true }): List[String] = {
    // TODO make more efficient
    // initialize listbuffer to save all strings found
    val strings = new ListBuffer[String]
    using(new BufferedReader(new InputStreamReader(new FileInputStream(file)))) { is =>
      // read one byte
      var byte: Int = is.read()
      // until EOF
      while (byte != -1 && strings.size < maxNumber) {
        // drop all bytes that are not ascii
        byte = dropWhile(is, !isASCIIPrintable(_))
        // check for EOF
        if (byte != -1) {
          // take all bytes that are ascii
          val (taken: String, b: Int) = takeWhile(is, isASCIIPrintable(_))
          // check if string has minimum length
          if (taken.length > minLength && filter(byte.toChar + taken)) {
            // save string with very first char/byte prepended, which had to be 
            // read by dropWhile
            if (taken.length <= maxLength)
              strings.append(byte.toChar + taken)
            else strings.append((byte.toChar + taken).take(maxLength) + "[...]")
          }
          byte = b
        }
      }
    }
    strings.toList
  }

  private def isASCIIPrintable(i: Int) = i >= 32 && i < 127

  private def takeWhile(is: Reader, f: Int => Boolean): (String, Int) = {
    // read first byte
    var byte: Int = is.read()
    val str = new StringBuffer()
    // read and save bytes as long as they fulfill f
    while (byte != -1 && f(byte)) {
      str.append(byte.toChar)
      byte = is.read()
    }
    // return string and last read byte
    (str.toString(), byte)
  }

  private def dropWhile(is: Reader, f: Int => Boolean): Int = {
    // read first byte
    var byte: Int = is.read()
    // read bytes as long as they fulfill f
    while (byte != -1 && f(byte)) {
      byte = is.read()
    }
    // return last read value, which does not fulfill f
    byte
  }

  /**
   * Reads all 2-byte (Unicode) based character-strings
   * contained in the file. Only printable ASCII characters are determined as string.
   *
   * @param file the file that is to be searched for strings
   * @param minLength the minimum length the strings shall have
   * @return List containing the Strings found
   */
  def readUnicodeStrings(file: File, minLength: Int): java.util.List[String] = {
    _readStrings(file, minLength, Integer.MAX_VALUE, Integer.MAX_VALUE, "UTF-16LE").asJava
  }

  def _readStrings(file: File, minLength: Int, maxLength: Int, maxNumber: Int, charset: String, isAllowed: String => Boolean = { _ => true }): List[String] = {
    val strings = new ListBuffer[String]
    var codepoints = ListBuffer.empty[Int]

    def maybeAppendToResults(cps: ListBuffer[Int]): Unit = {
      if (cps.length >= minLength && isAllowed(new String(cps.toArray, 0, cps.length))) {
        if (cps.length <= maxLength)
          strings.append(new String(cps.toArray, 0, cps.length))
        else strings.append(new String(cps.toArray, 0, maxLength) + "[...]")
      }
    }

    using(new BufferedReader(new InputStreamReader(new FileInputStream(file), charset))) { br =>
      var readInt = br.read()
      if (readInt != -1) codepoints += readInt
      var prev = 0
      while (readInt != -1 && strings.size < maxNumber) {
        if (readInt == 0) {
          maybeAppendToResults(codepoints)
          codepoints = ListBuffer.empty[Int]
        }
        prev = readInt
        readInt = br.read()
        if (readInt != -1) codepoints += readInt
      }
      maybeAppendToResults(codepoints)
    }
    //    strings.foreach { str => if (str.toLowerCase().contains("cheat")) println(str) }
    strings.toList
  }
}
