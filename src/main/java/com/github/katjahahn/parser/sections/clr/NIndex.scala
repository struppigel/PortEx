/**
 * *****************************************************************************
 * Copyright 2022 Karsten Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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

class GuidIndex(index : Int, val guidHeap : Option[GuidHeap]) extends NIndex(index) {

  override def toString(): String = {
    if (guidHeap.isDefined && index != 0) guidHeap.get.get(index).toString else "0x" + index.toHexString + " (index)"
  }

  def getValue(): Optional[UUID] = if(guidHeap.isDefined) {
    Optional.of(guidHeap.get.get(index))
  } else Optional.empty()
}

class StringIndex(index : Int, val stringsHeap : Option[StringsHeap]) extends NIndex(index) {

  override def toString(): String = {
    if (stringsHeap.isDefined) stringsHeap.get.get(index) else "idx 0x" + index.toHexString
  }

  def getValue(): Optional[String] = if(stringsHeap.isDefined) {
    Optional.of(stringsHeap.get.get(index))
  } else Optional.empty()
}
