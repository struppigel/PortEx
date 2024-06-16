package com.github.katjahahn.parser.sections.debug

import com.github.katjahahn.parser.PEData
import com.github.katjahahn.parser.IOUtil.loadBytes
import com.github.katjahahn.parser.ScalaIOUtil.using
import com.github.katjahahn.parser.IOUtil.NL

import java.io.RandomAccessFile

class ExtendedDLLCharacteristics(cetCompat : Boolean, forwardCfiCompat : Boolean) {
  def getInfo() : String = NL +
    "Extended DLL Characteristics:" + NL +
    "-----------------------------" + NL +
    "CET Compat: " + cetCompat + NL +
    "Foward CFI Compat: " + forwardCfiCompat + NL

}

object ExtendedDLLCharacteristics {

  val IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT = 0x0001
  val IMAGE_DLLCHARACTERISTICS_EX_FORWARD_CFI_COMPAT = 0x0040

  def getInstance(ptrToRaw: Long, pedata: PEData) : ExtendedDLLCharacteristics = {
    val maybeEx = apply(ptrToRaw, pedata)
    if  (maybeEx.isDefined) maybeEx.get
    else throw new IllegalStateException("Extended DLL Characteristics not readable")
  }

  def apply(ptrToRaw: Long, pedata: PEData): Option[ExtendedDLLCharacteristics] = {
    using(new RandomAccessFile(pedata.getFile, "r")) { raf =>
      val exCharSize = 1
      val exCharBits = loadBytes(ptrToRaw, exCharSize , raf)
      if (exCharBits.isEmpty) None else {
        val cetCompat = (exCharBits(0) & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT) != 0
        val forwardCfiCompat = (exCharBits(0) & IMAGE_DLLCHARACTERISTICS_EX_FORWARD_CFI_COMPAT) != 0
        Some(new ExtendedDLLCharacteristics(cetCompat, forwardCfiCompat))
      }
    }
  }
}