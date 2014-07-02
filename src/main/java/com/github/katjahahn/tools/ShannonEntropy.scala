package com.github.katjahahn.tools

import java.io.File
import java.io.FileInputStream

import scala.collection.JavaConverters.mapAsJavaMapConverter

import com.github.katjahahn.parser.PEData
import com.github.katjahahn.parser.sections.SectionLoader

import ShannonEntropy._

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
    val bytes = (new SectionLoader(data)).loadSection(sectionNumber).getBytes()
    entropy(bytes)
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

object ShannonEntropy {

  private val chunkSize = 1024
  private val byteSize = 256

  def main(args: Array[String]): Unit = {
//    val folder = new File("src/main/resources/testfiles")
//    for (file <- folder.listFiles) {
//      println("file: " + file.getName)
//      val data = PELoader.loadPE(file)
//      val ent = new ShannonEntropy(data)
//      ent._forSections.foreach(println)
//      println(data.getSectionTable().getInfo)
//      println()
//    }
    val str = "bla"
    println(List("", "bla").contains(str))
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
   * Calculates Shannon's Entropy for the file
   *
   * @param the file to calculate the entropy from
   * @return Shannon's Entropy for the file
   */
  def fileEntropy(file: File): Double = {
    val (byteCounts, total) = countBytes(file)
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

  private def countBytes(file: File): (Array[Long], Long) = {
    using(new FileInputStream(file)) { fis =>
      val bytes = Array.fill[Byte](chunkSize)(0)
      val byteCounts = Array.fill[Long](byteSize)(0L)
      var total: Long = 0L
      Iterator
        .continually(fis.read(bytes))
        .takeWhile(-1 !=)
        .foreach { _ =>
          List.fromArray(bytes).foreach { byte =>
            byteCounts((byte & 0xff)) += 1
            total += 1
          }
        }
      (byteCounts, total)
    }
  }

  private def using[A <: { def close(): Unit }, B](param: A)(f: A => B): B =
    try { f(param) } finally { param.close() }

}