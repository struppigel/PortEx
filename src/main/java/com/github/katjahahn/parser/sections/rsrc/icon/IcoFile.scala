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

package com.github.katjahahn.parser.sections.rsrc.icon

import com.github.katjahahn.parser.{ByteArrayUtil, PhysicalLocation}
import com.github.katjahahn.parser.ScalaIOUtil.using

import java.io._

/**
 * Represents a Windows ICO file.
 */
class IcoFile(
  private val iconDir: IconDir, private val peFile: File) {

  /**
   * Saves the ICO to the file path of dest.
   *
   * @param dest output file
   */
  def saveTo(dest: File): Unit = {
    using(new RandomAccessFile(peFile, "r")) { raf =>

      using(new FileOutputStream(dest)) { out =>
        writeHeader(out)
        val headerSize = 6L + iconDir.idEntries.size * 16L
        writeRawData(headerSize, out, raf)
      }
    }
  }

  /**
   * Retrieve input stream containing the bytes of the ICO data
   *
   * @return input stream with ICO data
   */
  def getInputStream(): InputStream = {
    using(new RandomAccessFile(peFile, "r")) { raf =>
      val os = new ByteArrayOutputStream();
      using(os) { out =>
        writeHeader(out)
        val headerSize = 6L + iconDir.idEntries.size * 16L
        writeRawData(headerSize, out, raf)
        return new ByteArrayInputStream(os.toByteArray());
      }
    }
  }

  /**
   * Retrieve byte array of ICO data
   *
   * @return byte array with ICO data
   */
  def getBytes(): Array[Byte] = {
    using(new RandomAccessFile(peFile, "r")) { raf =>
      val os = new ByteArrayOutputStream();
      using(os) { out =>
        writeHeader(out)
        val headerSize = 6L + iconDir.idEntries.size * 16L
        writeRawData(headerSize, out, raf)
        return os.toByteArray();
      }
    }
  }

  /**
   * Writes the ICO header
   * @param out the output stream
   */
  private def writeHeader(out: OutputStream): Unit = {
    out.write(ByteArrayUtil.intToWord(iconDir.idReserved))
    out.write(ByteArrayUtil.intToWord(iconDir.idType))
    out.write(ByteArrayUtil.intToWord(iconDir.idCount))
    for (entry <- iconDir.idEntries) {
      out.write(entry.bWidth & 0xff)
      out.write(entry.bHeight & 0xff)
      out.write(entry.bColorCount & 0xff)
      out.write(entry.bReserved & 0xff)
      out.write(ByteArrayUtil.intToWord(entry.wPlanes))
      out.write(ByteArrayUtil.intToWord(entry.wBitCount))
      out.write(ByteArrayUtil.longToDWord(entry.dwBytesInRes))
      out.write(ByteArrayUtil.longToDWord(entry.dwImageOffset))
    }
  }

  /**
   * Writes the raw data for every idEntry in the header.
   * 
   * @param headerSize the minimal offset to start writing
   * @param out the output stream
   * @param raf the input stream to read the raw data from
   */
  private def writeRawData(headerSize: Long, out: OutputStream, raf: RandomAccessFile): Unit = {
    val idEntries = iconDir.idEntries.sortBy { _.dwImageOffset }
    var offset = headerSize
    for (entry <- idEntries) {
      // fill space in between with zeroes
      while (offset < entry.dwImageOffset) {
        out.write(0)
        offset += 1
      }
      // write actual icon data
      raf.seek(entry.peLocation.from)
      while (offset < entry.dwImageOffset + entry.dwBytesInRes &&
        offset < entry.dwImageOffset + entry.peLocation.size) {
        val byte = raf.read()
        out.write(byte)
        offset += 1
      }
    }
  }
}

/**
 * Represents an icon directory
 * 
 * @param idReserved must be 0
 * @param idType Resource Type (must be 1 for icons)
 * @param idCount number of images
 * @param idEntries the entries for each image
 */
case class IconDir(idReserved: Int, idType: Int, idCount: Int, idEntries: List[IconDirEntry])

/**
 * Represents an icon directory entry
 * 
 * @param bWidth width of the image in pixels
 * @param bHeight height of the image in pixels
 * @param bColorCount Number of colors in image (0 if >= 8bpp)
 * @param bReserved reserved
 * @param wPlanes color planes
 * @param wBitCount
 * @param peLocation location of bytes in the pefile
 */
case class IconDirEntry(bWidth: Byte, bHeight: Byte, bColorCount: Byte,
  bReserved: Byte, wPlanes: Int, wBitCount: Int,
  dwBytesInRes: Long, dwImageOffset: Long,
  peLocation: PhysicalLocation)