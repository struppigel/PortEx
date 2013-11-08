package com.github.katjahahn.sections.idata

import com.github.katjahahn.sections.PESection

class ImportSection(
    private val idatabytes: Array[Byte], 
    private val virtualAdress: Integer
    ) extends PESection {
  
  override def read(): Unit = {}
  
  override def getInfo(): String = 
    """-------------
ImportSection
-------------""".stripMargin
    
  

}