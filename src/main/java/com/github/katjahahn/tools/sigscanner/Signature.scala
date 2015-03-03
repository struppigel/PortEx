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
package com.github.katjahahn.tools.sigscanner

import Signature._
import scala.Array.canBuildFrom
import com.github.katjahahn.parser.ScalaIOUtil._
import scala.PartialFunction._

/**
 * @author Katja Hahn
 *
 * Creates a signature instance with the values specified
 *
 * @param name the name of the packer or compiler
 * @param epOnly true iff only found at the entry point of the PE file
 * @param sigmature the byte signature, where the Option None denotes unknown
 * 				    bytes ("??" in signature file)
 */
class Signature(val name: String, val epOnly: Boolean, val signature: Array[Option[Byte]]) {
  
  def bytesMatched(): Int =
      signature.count(cond(_) { case Some(s) => true })

  override def toString(): String =
    s"""|name: $name
    	|signature: ${bytes2hex(signature, " ")}
	    |ep_only: $epOnly """.stripMargin

}

object Signature {

  /**
   * @param name name of packer or compiler
   * @param ep epOnly flag as string, will be converted to boolean true iff 
   * 		   the string is "true"
   * @param sig byte sequence as hex string, uknown bytes are marked as "??"
   * @return an instance of Signature with the fields applied
   */
  def apply(name: String, ep: String, sig: String): Signature = {
    val ep_only = ep.split("=")(1).trim == "true"
    val sigbytes = hex2bytes(sig.split("=")(1).trim)
    new Signature(name, ep_only, sigbytes)
  }
  
  /**
   * @param name name of packer or compiler
   * @param ep epOnly flag
   * @param sig byte sequence as hex string, uknown bytes are marked as "??"
   * @return an instance of Signature with the fields applied
   */
  def apply(name: String, ep: Boolean, sig: String): Signature = {
    val sigbytes = hex2bytes(sig)
    new Signature(name, ep, sigbytes)
  }

  /**
   * Converts a hex string representation to an array of option bytes. "??" is
   * converted to None.
   *
   * @param hex the hex string with ?? indicating unknown byte values
   * @return an array of option bytes with None indicating unknown values
   */
  def hex2bytes(hex: String): Array[Option[Byte]] = {
    val arr = hex.replaceAll("[^0-9A-Fa-f?]", "").sliding(2, 2).toArray
    arr.map(str => str match {
      case "??" => None
      case _ => Some(Integer.parseInt(str, 16).toByte)
    })
  }
}
