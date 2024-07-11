/**
 * *****************************************************************************
 * Copyright 2022 Karsten Hahn
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
package com.github.struppigel.parser.sections.clr

import com.github.struppigel.parser.StandardField

import java.lang.Long.toHexString
import java.util.UUID

/**
 * Field types for table entries in MSIL optimized stream
 */
abstract class CLRField(sfield : StandardField) {
  override def toString: String = sfield.getDescription + ": 0x" + toHexString(sfield.getValue)

  /**
   * Returns the value as an Object, using sometimes descriptive Strings and sometimes actual Long values
   * depending on the content.
   * @return
   */
  def getValueAsObject(): Object = sfield.getValue.asInstanceOf[Object]
  def getDescription: String = toString
  def getValue: Long = sfield.getValue
  def getName: String = sfield.getDescription
  def getOffset: Long = sfield.getOffset
  def setOptimizedStream(optStream : OptimizedStream): Unit = {/*do nothing*/}
  def toStandardField(): StandardField = new StandardField(sfield.getKey, this.getDescription, this.getValue, this.getOffset, sfield.getSize)
}

/**
 * Some fields have an index of some sort
 */
trait NIndexable { def getNIndex(): NIndex }

/**
 * Either unspecified field or fields containing constants
 * This is simply a represenation if nothing else about the Long value is known.
 * @param sfield
 */
case class CLRLongField(sfield : StandardField) extends CLRField(sfield) {
}

/**
 * The field represents a flag of some sort. As such it has an descriptive representation of the value,
 * which is specified in the description parameter.
 * @param sfield
 * @param description
 */
case class CLRFlagField(sfield : StandardField, valueDescription : String) extends CLRField(sfield) {
  override def toString: String = sfield.getDescription + ": " + valueDescription +
    " (0x" + sfield.getValue.toHexString + ")"
  override def getDescription: String = valueDescription
  override def getValueAsObject(): Object = valueDescription.asInstanceOf[Object]
}

/**
 * Field contains an index into #Strings
 * @param strIdx
 * @param sfield
 */
case class CLRStringField(strIdx : StringIndex, sfield : StandardField) extends CLRField(sfield) with NIndexable {
  override def getNIndex: NIndex = strIdx
  override def toString: String = sfield.getDescription + ": " + strIdx.toString()
  def getString: String = strIdx.getValue().get
  override def getDescription: String = strIdx.toString()
  override def getValueAsObject(): Object = strIdx.toString().asInstanceOf[Object]
}

/**
 * Field contains an index into #Blob
 * @param blobAddr
 * @param sfield
 */
case class CLRBlobField(blobIdx : BlobIndex, sfield : StandardField) extends CLRField(sfield) with NIndexable {
  override def getNIndex: NIndex = blobIdx
  override def getDescription: String = blobIdx.toString()
  override def toString: String = sfield.getDescription + ": " + blobIdx.toString()
  override def getValueAsObject(): Object = blobIdx.toString().asInstanceOf[Object]
}


/**
 * Field contains an index into #GUID
 * @param guidIdx
 * @param sfield
 */
case class CLRGuidField(guidIdx : GuidIndex, sfield : StandardField) extends CLRField(sfield) with NIndexable {
  override def getNIndex: NIndex = guidIdx
  override def toString: String = sfield.getDescription + ": " + guidIdx.toString()
  def getGuid: UUID = guidIdx.getValue().get
  override def getDescription: String = guidIdx.toString()
  override def getValueAsObject(): Object = guidIdx.toString().asInstanceOf[Object]
}

/**
 * Field contains a coded token. As such it is an index into to row of a specific table.
 * @param codedTokenIndex
 * @param sfield
 */
case class CLRCodedIndexField(codedTokenIndex: CodedTokenIndex, sfield : StandardField) extends CLRField(sfield) with NIndexable {

  /**
   * Provide optimized stream to make the toStrings method show better data
   * This cannot be done at creation of the object because the optimized stream is not loaded at this point.
   *
   * @param optStream
   */
  override def setOptimizedStream(optStream : OptimizedStream): Unit = {
    codedTokenIndex.setOptStream(optStream)
  }

  /**
   * The name of the field and the coded token value
   * @return
   */
  override def toString: String = sfield.getDescription + ": " + codedTokenIndex.toString()

  /**
   * A string describing the coded token value.
   * In contrast to the toString method it does not contain the name of the field.
   * @return description of coded token value
   */
  override def getDescription: String = "Coded token::" + codedTokenIndex.toString()

  /**
   * The coded token, in unaltered form
   * @return coded token
   */
  override def getValue: Long = codedTokenIndex.getCodedToken

  /**
   * The coded token index object
   * @return coded token index object
   */
  override def getNIndex(): NIndex = codedTokenIndex

  /**
   * Every coded token references a row in a table. This returns said row.
   * Note that the rows in these tables start at index 1!
   * @return the row this field is pointing to
   */
  def getReferencedRow(): Int = getNIndex().getIndex()

  /**
   * Every coded token references a row in a table. This returns the table as a CLRTableType.
   * @return the table this field is pointing into
   */
  def getReferencedTableType(): Option[CLRTableType] = {
    if(codedTokenIndex.getReferencedTableType().isPresent) Some(codedTokenIndex.getReferencedTableType().get)
    else None
  }

  override def getValueAsObject(): Object = codedTokenIndex.toStringShort().asInstanceOf[Object]
}
