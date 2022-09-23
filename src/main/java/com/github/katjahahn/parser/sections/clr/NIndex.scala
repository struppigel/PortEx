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

import java.util.{Optional, UUID}

class NIndex(val index : Int) {

  def getIndex(): Int = index

}

class CodedTokenIndex(codedToken : Long, tagType : TagType) extends NIndex((codedToken >> tagType.getSize).toInt) {

  def getCodedToken() : Long = codedToken

  def getReferencedTable(): CLRTableType = {
    val tag = codedToken & ((1L << tagType.getSize) - 1)
    tagType.getTableForTag(tag.toInt)
  }

  override def toString(): String =
    s"0x${codedToken.toHexString} -> row ${getIndex()} in ${getReferencedTable().name()}"
}

class GuidIndex(index : Int, val guidHeap : Option[GuidHeap]) extends NIndex(index) {

  override def toString(): String = {
    if (isValid && index != 0)
      guidHeap.get.get(index).toString
    else "0x" + index.toHexString + " (invalid index)"
  }

  def isValid() : Boolean = guidHeap.isDefined &&
    guidHeap.get.getSizeInBytes() > index &&
    index >= 0 // TODO > or >= ??

  def getValue(): Optional[UUID] = if(isValid) {
    Optional.of(guidHeap.get.get(index))
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
