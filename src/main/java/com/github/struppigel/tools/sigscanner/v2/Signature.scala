package com.github.struppigel.tools.sigscanner.v2

/*******************************************************************************
 * Copyright 2024 Karsten Hahn
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
 ******************************************************************************/


import org.apache.logging.log4j.LogManager

abstract class Signature(val name : String, val scanLocations : List[ScanLocation]) {
  def matches(bytes: Array[Byte]) : (Boolean, Int)
}

class PatternSignature(override val name: String, override val scanLocations : List[ScanLocation],
                       val pattern: Pattern) extends Signature(name, scanLocations) {

  def _matches(bytes: Array[Byte], offset: Int): (Boolean, Int) = {
    val result = pattern.matches(bytes)
    if(result == true) return (true, offset)
    else if (bytes.length < pattern.minMatchLength()) return (false, offset)
    else return _matches(bytes.drop(1), offset + 1)
  }

  override def matches(bytes: Array[Byte]): (Boolean, Int) =
    _matches(bytes, 0)

  override def toString(): String =
    s"""|name: $name
    	|pattern: ${pattern.toString()}
	    |locs: $scanLocations""".stripMargin

}

object PatternSignature {

  private val logger = LogManager.getLogger(PatternSignature.getClass.getName)

  def apply(name: String, scanLocations : List[ScanLocation], patternString : String): PatternSignature =
    new PatternSignature(name, scanLocations, PatternParser.parseInit(patternString))

  def newInstance(name: String, scanLocations : List[ScanLocation], patternString : String): PatternSignature =
    apply(name, scanLocations, patternString)

}

