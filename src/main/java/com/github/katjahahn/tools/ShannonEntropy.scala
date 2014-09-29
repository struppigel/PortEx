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

  private val chunkSize = 1024
  private val byteSize = 256

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
   * Calculates Shannon's Entropy for the file
   *
   * @param the file to calculate the entropy from
   * @return Shannon's Entropy for the file
   */
  def fileEntropy(file: File): Double = {
    val (byteCounts, total) = countBytes(file)
    entropy(byteCounts, total)
  }

  def entropy(file: File, offset: Long, size: Long): Double = {
    val (byteCounts, total) = countBytes(file, offset, size)
    entropy(byteCounts, total)
  }

  private def entropy(byteCounts: Array[Long], total: Long): Double =
    List.fromArray(byteCounts).foldRight(0.0) { (counter, entropy) =>
      if (counter != 0) {
        val p: Double = 1.0 * counter / total
        entropy - p * (math.log(p) / math.log(byteSize))
      } else entropy
    }

  private def countBytes(bytes: Array[Byte]): (Array[Long], Long) = {
    val byteCounts = Array.fill[Long](byteSize)(0L)
    var total: Long = 0L
    List.fromArray(bytes).foreach { byte =>
      val index = (byte & 0xff)
      byteCounts(index) += 1L
      total += 1L
    }
    (byteCounts, total)
  }

  private def countBytes(file: File): (Array[Long], Long) =
    countBytes(file, 0L, file.length)

  private def countBytes(file: File, offset: Long, size: Long): (Array[Long], Long) = {
    using(new FileInputStream(file)) { fis =>
      val bytes = Array.fill[Byte](chunkSize)(0)
      val byteCounts = Array.fill[Long](byteSize)(0L)
      var total: Long = 0L
      var readbytes = 0L
      Iterator
        .continually(fis.read(bytes))
        .takeWhile(-1 !=)
        .foreach { _ =>
          List.fromArray(bytes).foreach { byte =>
            if (readbytes >= offset && readbytes < offset + size) {
              byteCounts((byte & 0xff)) += 1
              total += 1
            }
            readbytes += 1
          }
        }
      (byteCounts, total)
    }
  }

}