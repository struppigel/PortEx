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
package com.github.katjahahn.parser.sections.clr

import com.github.katjahahn.parser.{ByteArrayUtil, ScalaIOUtil}

import java.util.{Optional, UUID}

class NIndex(val index : Int) {

  def getIndex(): Int = index

}

class CodedTokenIndex(codedToken : Long, tagType : TagType) extends NIndex((codedToken >> tagType.getSize).toInt) {

  private var optStream : Option[OptimizedStream] = None

  // must be set after loading the optimized stream, at which point all CodedTokenIndices are already created
  // set this to make the toStrings method show more relevant data
  def setOptStream(optimizedStream : OptimizedStream) {
    this.optStream = Some(optimizedStream) }

  def getCodedToken: Long = codedToken

  def getReferencedTableType(): Optional[CLRTableType] = {
    val tag = codedToken & ((1L << tagType.getSize) - 1)
    tagType.getTableForTag(tag.toInt)
  }

  override def toString(): String = {
    if(optStream.isDefined && getReferencedTableType().isPresent && optStream.get.getCLRTable(getReferencedTableType().get).isDefined) {
      val referencedTable = optStream.get.getCLRTable(getReferencedTableType().get).get
      val maybeEntry = referencedTable.getEntryByRow(getIndex())
      if(maybeEntry.isDefined) {
        return s"${maybeEntry.get.getShortDescription}"
      }
    }
    if(getReferencedTableType().isPresent)
      s"0x${codedToken.toHexString} -> row ${getIndex()} in ${getReferencedTableType().get.name}"
    else s"0x${codedToken.toHexString} -> row ${getIndex()} into nonexisting table"
  }
}

class GuidIndex(index : Int, val guidHeap : Option[GuidHeap]) extends NIndex(index) {

  override def toString(): String = {
    if (isValid)
      guidHeap.get.get(index).toString
    else if (index == 0)
      "0x" + index.toHexString + " (not set)"
    else
      "0x" + index.toHexString + " (invalid index)"
  }

  def isValid() : Boolean = guidHeap.isDefined &&
    guidHeap.get.getNumberOfGuids() >= index && index > 0

  def getValue(): Optional[UUID] = if(isValid) {
    Optional.of(guidHeap.get.get(index))
  } else Optional.empty()
}

class BlobIndex(index : Int, val blobHeap : Option[BlobHeap]) extends NIndex(index) {

  override def toString(): String = {
    val displayableContentLength = 0x50
    if (isValid && index != 0) {
      val content = blobHeap.get.get(index)
      if (content.length <= displayableContentLength)
        ByteArrayUtil.bytesToAsciiHexMix(content)
      else
        ByteArrayUtil.bytesToAsciiHexMix(content.slice(0,displayableContentLength)) + "... (" +content.size+ " bytes)"
    }
    else if (index == 0)
      "0x" + index.toHexString
    else
      "0x" + index.toHexString + " (invalid index)"
  }

  def isValid() : Boolean = blobHeap.isDefined &&
    blobHeap.get.getSizeInBytes() > index &&
    index >= 0

  def getValue(): Optional[Array[Byte]] = if(isValid) {
    Optional.of(blobHeap.get.get(index))
  } else Optional.empty()
}

class StringIndex(index : Int, val stringsHeap : Option[StringsHeap]) extends NIndex(index) {

  override def toString(): String = {
    if (isValid && index != 0)
      stringsHeap.get.get(index)
    else "0x" + index.toHexString
  }

  def isValid() : Boolean = stringsHeap.isDefined &&
    stringsHeap.get.getSizeInBytes() > index &&
    index >= 0 // TODO > or >= ??

  def getValue(): Optional[String] = if(isValid) {
    Optional.of(stringsHeap.get.get(index))
  } else Optional.empty()
}
