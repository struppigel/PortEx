/*******************************************************************************
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
 ******************************************************************************/
package com.github.katjahahn.tools

import com.github.katjahahn.parser.ScalaIOUtil.using
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.parser.PELoader
import java.io.RandomAccessFile

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
    val file = new File("/home/deque/portextestfiles/simile.exe")
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
    (_readASCIIStrings(file, minLength) ::: _readUnicodeStrings(file, minLength)).asJava
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
    _readASCIIStrings(file, minLength).asJava
  }

  def _readASCIIStrings(file: File, minLength: Int): List[String] = {
    // TODO make more efficient
    // initialize listbuffer to save all strings found
    val strings = new ListBuffer[String]
    using(new FileInputStream(file)) { is =>
      // read one byte
      var byte: Int = is.read()
      // until EOF
      while (byte != -1) {
        // drop all bytes that are not ascii
        byte = dropWhile(is, !isASCIIPrintable(_))
        // check for EOF
        if (byte != -1) {
          // take all bytes that are ascii
          val (taken, b) = takeWhile(is, isASCIIPrintable(_))
          // check if string has minimum length
          if (taken.length() > minLength) {
            // save string with very first char/byte prepended, which had to be 
            // read by dropWhile
            strings.append(byte.toChar + taken)
          }
          byte = b
        }
      }
    }
    strings.toList
  }

  private def isASCIIPrintable(i: Int) = i >= 32 && i < 127

  private def takeWhile(is: InputStream, f: Int => Boolean): (String, Int) = {
    // read first byte
    var byte: Int = is.read()
    val str = new StringBuffer()
    // read and save bytes as long as they fulfill f
    while (byte != -1 && f(byte)) {
      str.append(byte.toChar)
      byte = is.read();
    }
    // return string and last read byte
    (str.toString(), byte)
  }

  private def dropWhile(is: InputStream, f: Int => Boolean): Int = {
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
    _readUnicodeStrings(file, minLength).asJava
  }

  //TODO not really tested
  def _readUnicodeStrings(file: File, minLength: Int): List[String] = {
    val strings = new ListBuffer[String]
    var str = new StringBuilder()
    using(new FileInputStream(file)) { is =>
      var prev: Int = is.read()
      if (prev == -1) return strings.toList
      var byte: Int = is.read()
      var lastWasASCII = false

      while (prev != -1 && byte != -1) {
        val c = (prev << 8) + byte
        if (isASCIIPrintable(c)) {
          str.append(c)
        } else if (lastWasASCII) {
          if (str.length > minLength) {
            strings.append(str.toString)
          }
          str = new StringBuilder()
        } 
        lastWasASCII = isASCIIPrintable(c)
        prev = is.read()
        if (prev != -1) byte = is.read()
      }

    }
    strings.toList
  }
}
