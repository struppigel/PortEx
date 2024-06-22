/**
 * *****************************************************************************
 * Copyright 2014 Katja Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ****************************************************************************
 */

package com.github.struppigel.parser.sections.pdata

import com.github.struppigel.parser.IOUtil.{NL, SpecificationFormat}
import com.github.struppigel.parser.coffheader.MachineType._
import com.github.struppigel.parser.sections.SectionLoader.LoadInfo
import ExceptionSection._
import com.github.struppigel.parser.coffheader.MachineType
import com.github.struppigel.parser.optheader.DataDirectoryKey
import com.github.struppigel.parser.sections.{SectionLoader, SpecialSection}
import com.github.struppigel.parser.{FileFormatException, IOUtil, MemoryMappedPE, PELoader, PhysicalLocation, StandardField}

import java.io.File
import scala.collection.JavaConverters._

//TODO getInfo shows empty values, separate different formats, test different formats
class ExceptionSection private(
                                offset: Long,
                                private val directory: ExceptionDirectory) extends SpecialSection {

  override def isEmpty(): Boolean = directory.isEmpty

  def getField(key: ExceptionEntryKey): StandardField = directory(key)

  def get(key: ExceptionEntryKey): Long = directory(key).getValue

  def getExceptionFields(): java.util.Map[ExceptionEntryKey, StandardField] = directory.asJava

  def getInfo(): String = directory.values.mkString(NL)

  def getOffset(): Long = offset

  //FIXME implement
  def getSize(): Long = 0L

  def getPhysicalLocations(): java.util.List[PhysicalLocation] =
    (new PhysicalLocation(getOffset, getSize) :: Nil).asJava
}

object ExceptionSection {

  type ExceptionDirectory = Map[ExceptionEntryKey, StandardField]

  private val mipsspec = "pdatamipsspec"
  private val wincespec = "pdatawincespec"
  private val x64spec = "pdatax64spec"
  private val armv7spec = "pdataarmv7spec"

  private val machineToSpec =
    Map(ARM -> wincespec, POWERPC -> wincespec, SH3 -> wincespec,
      SH3DSP -> wincespec, SH4 -> wincespec, THUMB -> wincespec,

      R4000 -> mipsspec, MIPS16 -> mipsspec, MIPSFPU -> mipsspec,
      MIPSFPU16 -> mipsspec, WCEMIPSV2 -> mipsspec,

      AMD64 -> x64spec, IA64 -> x64spec,
      ARMNT -> armv7spec)

  //TODO wincespec!
  def apply(mmbytes: MemoryMappedPE, machine: MachineType,
            virtualAddress: Long, offset: Long): ExceptionSection = {
    if (!machineToSpec.contains(machine)) {
      throw new IllegalArgumentException("spec for machine type not found: " + machine)
    }
    val spec = machineToSpec(machine)
    //    println("using spec: " + spec)
    val format = new SpecificationFormat(0, 1, 2, 3)
    val pdatabytes = mmbytes.slice(virtualAddress, mmbytes.length + virtualAddress)
    val directory = IOUtil.readHeaderEntries(classOf[ExceptionEntryKey],
      format, spec, pdatabytes.clone, offset).asScala.toMap
    new ExceptionSection(offset, directory)
  }

  //TODO refactor parameter list
  def newInstance(li: LoadInfo): ExceptionSection = {
    val key = li.data.getCOFFFileHeader().getMachineType()
    if (!machineToSpec.contains(key))
        throw new FileFormatException("spec machine type not found: " + key)
    else
      apply(li.memoryMapped, key, li.va, li.fileOffset)
  }

  def main(args: Array[String]): Unit = {
    val folder = new File("portextestfiles/testfiles")
    for (file <- folder.listFiles) {
      val data = PELoader.loadPE(file)
      val entries = data.getOptionalHeader().getDataDirectory()
      if (entries.containsKey(DataDirectoryKey.EXCEPTION_TABLE)) {
        try {
          val pdata = new SectionLoader(data).loadExceptionSection()
          println("file: " + file.getName)
          println(pdata.getInfo)
          println()
        } catch {
          case e: IllegalStateException => println(e.getMessage())
        }
      }
    }
  }

}