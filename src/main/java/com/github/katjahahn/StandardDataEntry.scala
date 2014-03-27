/*******************************************************************************
 * Copyright 2014 Katja Hahn
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
package com.github.katjahahn

import scala.collection.mutable.ListBuffer
import scala.collection.JavaConverters._
import com.github.katjahahn.PEModule._
import com.github.katjahahn.ByteArrayUtil._
//TODO this is not used at all by now
class StandardDataEntry[K <: Enumeration] (
  private val entrybytes: Array[Byte],
  private val specLocation: String
		) extends PEModule {
  
  private val specification = IOUtil.readMap(specLocation).asScala.toMap
  
  var entries : List[StandardEntry] = Nil
  
  override def read(): Unit = {
    val buffer = ListBuffer.empty[StandardEntry]
    for ((key, specs) <- specification) {
      val description = specs(0)
      val offset = Integer.parseInt(specs(1))
      val size = Integer.parseInt(specs(2))
	  val value = getBytesIntValue(entrybytes, offset, size)
	  val entry = new StandardEntry(key, description, value)
	  buffer += entry
	}
    entries = buffer.toList
  }
 
  def apply(key: K#Value): Long = {
    entries.find(x => x.key.toString == key.toString) match {
      case Some(e) => e.value 
      case None => throw new IllegalArgumentException
    }
  }
  
  override def getInfo(): String = entries.mkString(NL)
  
  override def toString(): String = getInfo()

}
