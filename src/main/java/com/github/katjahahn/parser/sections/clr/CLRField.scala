package com.github.katjahahn.parser.sections.clr

import com.github.katjahahn.parser.StandardField

import java.util.UUID

/**
 * Field types for table entries
 */
abstract class CLRField(){
  def getDescription: String = toString
  def getValue: Long
}

trait NIndexable { def getNIndex(): NIndex }

case class CLRLongField(sfield : StandardField) extends CLRField {
  override def toString: String = sfield.toString
  override def getValue: Long = sfield.getValue
}

case class CLRFlagField(sfield : StandardField, description : String) extends CLRField {
  override def toString: String = sfield.getDescription + ": " + description +
    " (0x" + sfield.getValue.toHexString + ")"
  override def getValue: Long = sfield.getValue
  override def getDescription: String = description
}

case class CLRStringField(strIdx : StringIndex, sfield : StandardField) extends CLRField with NIndexable {
  override def getNIndex: NIndex = strIdx
  override def toString: String = sfield.getDescription + ": " + strIdx.toString()
  def getString: String = strIdx.getValue().get
  override def getValue: Long = sfield.getValue
  override def getDescription: String = strIdx.toString()
}

case class CLRGuidField(guidIdx : GuidIndex, sfield : StandardField) extends CLRField with NIndexable {
  override def getNIndex: NIndex = guidIdx
  override def toString: String = sfield.getDescription + ": " + guidIdx.toString()
  def getGuid: UUID = guidIdx.getValue().get
  override def getValue: Long = sfield.getValue
  override def getDescription: String = guidIdx.toString()
}
