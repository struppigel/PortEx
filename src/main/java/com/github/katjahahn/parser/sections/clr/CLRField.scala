package com.github.katjahahn.parser.sections.clr

import com.github.katjahahn.parser.StandardField

import java.util.UUID

/**
 * Field types for table entries
 */
abstract class CLRField(){
}

trait NIndexable { def getNIndex(): NIndex }

case class CLRLongField(sfield : StandardField) extends CLRField {
  override def toString: String = sfield.toString()
}

case class CLRStringField(strIdx : StringIndex, sfield : StandardField) extends CLRField with NIndexable {
  override def getNIndex: NIndex = strIdx
  override def toString: String = sfield.getDescription + ": " + strIdx.toString()
  def getString: String = strIdx.getValue().get
}

case class CLRGuidField(guidIdx : GuidIndex, sfield : StandardField) extends CLRField with NIndexable {
  override def getNIndex: NIndex = guidIdx
  override def toString: String = sfield.getDescription + ": " + guidIdx.toString()
  def getGuid: UUID = guidIdx.getValue().get
}
