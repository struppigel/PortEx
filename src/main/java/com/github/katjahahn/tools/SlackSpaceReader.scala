package com.github.katjahahn.tools

import com.github.katjahahn.PEData
import com.github.katjahahn.PELoader
import java.io.File

class SlackSpaceReader(private val data: PEData) {
  
  type SpaceRange = (Long, Long)
  
  def readMSDOSPESigSpace(): Unit = {
    val module = data.readMSDOSLoadModule()
    val headerSize = data.getMSDOSHeader().getHeaderSize()
    val imageSize = module.getImageSize()
    val endpoint = headerSize + imageSize
    val peSigOffset = data.getPESignature().getPEOffset()
    (endpoint, peSigOffset)
  }
  
  def getInfo(): String = ""

}

object SlackSpaceReader {
  
  def main(args: Array[String]): Unit = {
    val data = PELoader.loadPE(new File("WinRar.exe"))
    val reader = new SlackSpaceReader(data)
    println(reader.getInfo)
  }
  
}