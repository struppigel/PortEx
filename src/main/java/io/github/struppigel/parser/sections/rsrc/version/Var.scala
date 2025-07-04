/**
 * *****************************************************************************
 * Copyright 2016 Katja Hahn
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

package io.github.struppigel.parser.sections.rsrc.version

class Var(
  val wLength: Int,
  val wValueLength: Int,
  val wType: Int,
  val szKey: String,
  val padding: Int,
  val children: Array[StringTable]){
  
  override def toString(): String =
    s"""|wLength: $wLength
        |wValueLength: $wValueLength
        |wType: $wType
        |szKey: $szKey
        |padding: $padding
      """.stripMargin
}

object Var {
  
  //TODO Implement
  
  

}