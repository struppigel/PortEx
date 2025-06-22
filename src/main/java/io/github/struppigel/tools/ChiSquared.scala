package io.github.struppigel.tools

import io.github.struppigel.parser.ScalaIOUtil.using
import ChiSquared.calculate
import io.github.struppigel.parser.{PEData, PELoader}
import io.github.struppigel.parser.sections.SectionLoader

import java.io.{File, RandomAccessFile}
import scala.collection.JavaConverters.mapAsJavaMapConverter
import scala.language.postfixOps

/**
 * Tool to calculate Chi squared for entire files, byte arrays or sections
 * of a PE.
 *
 * @author Karsten Hahn
 */
class ChiSquared(private val data: PEData) {

  /**
   * Calculates Shannon's Entropy for the file
   *
   * @return Shannon's Entropy for the file
   */
  def forFile(): Double = {
    val file = data.getFile
    calculate(file, 0L, file.length())
  }

  /**
   * Calculates the entropy for the section with the sectionNumber.
   *
   * @param sectionNumber number of the section
   * @return entropy of the section
   */
  def forSection(sectionNumber: Int): Double = {
    val section = new SectionLoader(data).loadSection(sectionNumber)
    calculate(data.getFile, section.getOffset, section.getSize)
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
    val sectionNr = data.getCOFFFileHeader.getNumberOfSections
    (for (i <- 1 to sectionNr) yield (i, forSection(i))) toMap
  }
}


/**
 * Chi squared calculation on a data stream with random data as expected data.
 */
object ChiSquared {

  /** size of one chunk that is used to read bytes from the file */
  private val chunkSize = 1024
  /** size of one byte is surprisingly 256 */
  private val byteSize = 256

  def newInstance(file: File): ChiSquared = {
    val data = PELoader.loadPE(file)
    new ChiSquared(data)
  }

  /**
   * Calculate Chi squared value for given file
   * Formula: chi_2 = sum(squared(o_i - e_i)/e_i)
   * @param file the file to calculate the chi2 from
   * @param offset the offset to start calculating the chi2 from
   * @param size the number of bytes that make up the part of the file that is
   *        used to calculate the chi2 from
   * @return Chi squared value for given byte array
   */
  def calculate(file: File, offset: Long, size: Long): Double = {
    val (byteCounts, total) = countBytes(file, offset, size)
    // calculate expected frequency
    // since we assume random data, it is even distribution for each byte
    val expected : Double = 1.0 * total / byteSize
    // calculate and return chi squared
    byteCounts.toList.foldRight(expected) { (observed, chi) =>
      chi + ( math.pow(observed - expected, 2) / expected )
    }
  }

  /**
   * Calculate Chi squared value
   * Formula: chi_2 = sum(squared(o_i - e_i)/e_i)
   * @param bytes array of bytes to calculate the chi2
   * @return Chi squared value for given byte array
   */
  def calculate(bytes: Array[Byte]): Double = {
    val (byteCounts, total) = countBytes(bytes)
    // calculate expected frequency
    // since we assume random data, it is even distribution for each byte
    val expected : Double = 1.0 * total / byteSize
    // calculate and return chi squared
    byteCounts.toList.foldRight(expected) { (observed, chi) =>
      chi + ( math.pow(observed - expected, 2) / expected )
    }
  }

  /**
   * Determine absolute frequencies of the byte values.
   *
   * @param bytes array of bytes to count the byte values from
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
      val index = byte & 0xff
      // count byte, index denotes the read byte value
      byteCounts(index) += 1L
      // add byte to total
      total += 1L
    }
    // return our tuple
    (byteCounts, total)
  }

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
