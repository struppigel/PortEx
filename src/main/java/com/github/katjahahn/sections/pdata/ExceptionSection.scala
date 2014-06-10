package com.github.katjahahn.sections.pdata

import com.github.katjahahn.sections.SpecialSection
import com.github.katjahahn.coffheader.MachineType
import com.github.katjahahn.coffheader.MachineType._

class ExceptionSection private (offset: Long) extends SpecialSection {

  def getInfo(): String = ""

  def getOffset(): Long = offset
}

object ExceptionSection {

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

  def apply(sectionbytes: Array[Byte], machine: MachineType,
    virtualAddress: Long, offset: Long): ExceptionSection = {

    new ExceptionSection(offset)
  }

}