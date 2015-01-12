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

import java.io.File
import java.io.FileInputStream
import scala.collection.JavaConverters.mapAsJavaMapConverter
import com.github.katjahahn.parser.ScalaIOUtil.using
import com.github.katjahahn.parser.PEData
import com.github.katjahahn.parser.sections.SectionLoader
import ShannonEntropy._
import java.io.RandomAccessFile
import com.github.katjahahn.parser.PELoader

/**
 * Tool to calculate Shannon's Entropy for entire files, byte arrays or sections
 * of a PE.
 *
 * Example code:
 * <pre>
 * {@code
 * File file = new File("WinRar.exe");
 * PEData data = PELoader.loadPE(file);
 * ShannonEntropy entropy = new ShannonEntropy(data);
 * int sectionNr = 1;
 * System.out.println("Entropy for section " + sectionNr + ": " + entropy.forSection(sectionNr));
 * }
 * </pre>
 *
 * @author Katja Hahn
 */
class ShannonEntropy(private val data: PEData) {

  /**
   * Calculates Shannon's Entropy for the file
   *
   * @return Shannon's Entropy for the file
   */
  def forFile(): Double = {
    val file = data.getFile()
    val (byteCounts, total) = countBytes(file)
    entropy(byteCounts, total)
  }

  /**
   * Calculates the entropy for the section with the sectionNumber.
   *
   * @param sectioNumber number of the section
   * @return entropy of the section
   */
  def forSection(sectionNumber: Int): Double = {
    val section = (new SectionLoader(data)).loadSection(sectionNumber)
    entropy(data.getFile, section.getOffset(), section.getSize())
  }

  /**
   * Calculates the entropy for all sections of the file and returns a map with
   * the section numbers as keys and their entropy as values.
   *
   * @return map with section number as keys and entropy as values
   */
  def forSections(): java.util.Map[java.lang.Integer, java.lang.Double] =
    _forSections().map(t => (t._1: java.lang.Integer, t._2: java.lang.Double)).asJava

  /**
   * Calculates the entropy for all sections of the file
   *
   * @return map with section number as keys and entropy as values
   */
  private def _forSections(): Map[Int, Double] = {
    val sectionNr = data.getCOFFFileHeader().getNumberOfSections()
    (for (i <- 1 to sectionNr) yield (i, forSection(i))) toMap
  }
}

/**
 * Responsible to calculate non-file-specific entropies, i.e. for byte arrays.
 */
object ShannonEntropy {

  /** size of one chunk that is used to read bytes from the file */
  private val chunkSize = 1024
  /** size of one byte is surprisingly 256 */
  private val byteSize = 256
  
  def newInstance(file: File): ShannonEntropy = {
    val data = PELoader.loadPE(file)
    new ShannonEntropy(data)
  }

  /**
   * Calculates Shannon's Entropy for the byte array
   *
   * @param bytes the input array
   * @return Shannon's Entropy for the byte array
   */
  def entropy(bytes: Array[Byte]): Double = {
    val (byteCounts, total) = countBytes(bytes)
    entropy(byteCounts, total)
  }

  /**
   * Calculates Shannon's Entropy for the specified part of the file
   *
   * @param file the file to calculate the entropy from
   * @param offset the offset to start calculating the entropy from
   * @param size the number of bytes that make up the part of the file that is
   *        used to calculate the entropy from
   * @return Shannon's Entropy for the part of the file specified by offset and size
   */
  def entropy(file: File, offset: Long, size: Long): Double = {
    val (byteCounts, total) = countBytes(file, offset, size)
    entropy(byteCounts, total)
  }

  /**
   * Calculates Shannon's Entropy for the specified byte counts and total of
   * bytes.
   *
   * @return Shannon's Entropy
   */
  private def entropy(byteCounts: Array[Long], total: Long): Double =
    // iterate through byte counts, start fold with initial entropy 0.0
    byteCounts.toList.foldRight(0.0) { (counter, entropy) =>
      // if byte count is zero, just return current entropy
      if (counter != 0) {
        // calculate the relative frequency of the byte value
        val p: Double = 1.0 * counter / total
        // calculate the resulting entropy
        entropy - p * (math.log(p) / math.log(byteSize))
      } else entropy
    }

  /**
   * Determine absolute frequencies of the byte values.
   *
   * @param bytes
   * @return Tuple with an byte sized array (containing the byte counts) and
   * the total of bytes read
   */
  private def countBytes(bytes: Array[Byte]): (Array[Long], Long) = {
    // initialize byte sized array that will contain the byte counts
    val byteCounts = Array.fill[Long](byteSize)(0L)
    // initialize total
    var total: Long = 0L
    // count each byte in the given array
    bytes.toList.foreach { byte =>
      // byte to int conversion
      val index = (byte & 0xff)
      // count byte, index denotes the read byte value
      byteCounts(index) += 1L
      // add byte to total
      total += 1L
    }
    // return our tuple
    (byteCounts, total)
  }

  /**
   * Count all bytes of the given file.
   * 
   * @param file the file to count the byte from
   * @return tuple containing the byte counts and the number of bytes read
   */
  private def countBytes(file: File): (Array[Long], Long) =
    countBytes(file, 0L, file.length)

  /**
   * Determine the relative frequences of the bytes in the part of the files that
   * is specified by offset and size.
   *
   * @param file the file to count the bytes from
   * @param offset file offset to the start the count from
   * @param size the number of bytes to count
   * @return tuple containing the byte counts and the actual number of bytes
   * that was read (may differ from size if EOF reached)
   */
  private def countBytes(file: File, offset: Long, size: Long): (Array[Long], Long) = {
    using(new RandomAccessFile(file, "r")) { raf =>
      // initialize chunk sized byte array to save read bytes in
      val chunk = Array.fill[Byte](chunkSize)(0)
      // initialize byte sized array that will contain the byte counts
      val byteCounts = Array.fill[Long](byteSize)(0L)
      // initialize the total of bytes counted
      var totalCounted: Long = 0L
      // initialize total of bytes read, starting with offset bytes
      // read bytes are not necessarily counted
      var bytesReadTotal = offset
      // point raf to offset
      raf.seek(offset)
      Iterator
        // read up to chunkSize bytes into chunk
        .continually(raf.read(chunk))
        // until EOF is reached or enough bytes have been read for given range
        .takeWhile { bytesRead =>
          bytesRead != -1 && bytesReadTotal < offset + size
        }
        // count bytes for each chunk
        .foreach { bytesRead =>
          // take only the bytes that were actually read
          val bytes = chunk.toList.take(bytesRead)
          // count each byte that is within the specified range
          bytes.foreach { byte =>
            if (bytesReadTotal >= offset && bytesReadTotal < offset + size) {
              // byte to integer conversion
              val index = byte & 0xff
              // count byte
              byteCounts(index) += 1
              // add one to total count
              totalCounted += 1
            }
            // update readbytes
            bytesReadTotal += 1
          }
        }
      // return tuple of byte counts and total bytes counted
      (byteCounts, totalCounted)
    }
  }

}