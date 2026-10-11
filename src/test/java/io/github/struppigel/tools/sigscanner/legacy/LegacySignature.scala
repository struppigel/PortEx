/**
 * *****************************************************************************
 * Copyright 2014 Karsten Philipp Boris Hahn
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
package io.github.struppigel.tools.sigscanner.legacy

import org.apache.logging.log4j.LogManager

import scala.PartialFunction._

/**
 * Frozen copy of the PortEx 5.x (v1) signature class.
 * <p>
 * Only used as a baseline for the differential and performance tests of the
 * signature scanner. Do not change the behaviour of this class.
 */
class LegacySignature(val name: String, val epOnly: Boolean,
    val pattern: Array[Option[Byte]]) {

  def bytesMatched(): Int =
      pattern.count(cond(_) { case Some(s) => true })

  def signatureString(): String = LegacySignature.bytes2hex(pattern, " ")

  override def toString(): String =
    s"""|name: $name
    	|signature: $signatureString
	    |ep_only: $epOnly""".stripMargin

}

object LegacySignature {

  private val logger = LogManager.getLogger(LegacySignature.getClass.getName)

  def apply(name: String, ep: Boolean, sig: String): LegacySignature = {
    apply(name, ep, sig, 0, 0L, None)
  }

  /**
   * As in v1, addOffset, untilOffset and isDotNet are dropped.
   */
  def apply(name: String, ep: Boolean, sig: String, addOffset: Int, untilOffset: Long, isDotNet : Option[Boolean]): LegacySignature = {
    // convert quotes to hex string representation
    val quote = '\''
    var inQuote = false
    var convertedSig = sig.toList.foldRight(""){(ch, concat) =>
      if(ch == quote) {
        inQuote = !inQuote
        concat
      } else if(inQuote) {
        val convertedChar = Integer.toHexString(ch & 0xFF)
        convertedChar + concat
      } else {
        ch + concat
      }
    }
    // convert hex string to byte array
    val sigbytes = hex2bytes(convertedSig)
    // create signature
    new LegacySignature(name, ep, sigbytes)
  }

  /**
   * Converts a hex string representation to an array of option bytes. "??" is
   * converted to None.
   */
  def hex2bytes(hex: String): Array[Option[Byte]] = {
    val arr = hex.replaceAll("[^0-9A-Fa-f?]", "").sliding(2, 2).toArray
    arr.map(str => str match {
      case "??" => None
      case _ => Some(Integer.parseInt(str, 16).toByte)
    })
  }

  /**
   * Copy of the former ScalaIOUtil.bytes2hex for option byte arrays.
   */
  def bytes2hex(bytes: Array[Option[Byte]], sep: String): String = {
    bytes.foldLeft("")((s, b) => b match {
      case None => s + sep + "??"
      case _ => s + sep + "%02x".format(b.get)
    })
  }
}
