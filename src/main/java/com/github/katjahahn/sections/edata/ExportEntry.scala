package com.github.katjahahn.sections.edata

class ExportEntry (
    val symbolRVA: Long, 
    val name: String, 
    val ordinal: Int) extends Equals {
  
  override def toString(): String = s"""${name}, ${ordinal}, 0x${java.lang.Long.toHexString(symbolRVA)}"""
  
  def canEqual(other: Any) = {
      other.isInstanceOf[com.github.katjahahn.sections.edata.ExportEntry]
    }
  
  override def equals(other: Any) = {
      other match {
        case that: com.github.katjahahn.sections.edata.ExportEntry => that.canEqual(ExportEntry.this) && symbolRVA == that.symbolRVA && name == that.name && ordinal == that.ordinal
        case _ => false
      }
    }
  
  override def hashCode() = {
      val prime = 41
      prime * (prime * (prime + symbolRVA.hashCode) + name.hashCode) + ordinal.hashCode
    }

}