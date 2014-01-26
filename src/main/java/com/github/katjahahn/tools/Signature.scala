package com.github.katjahahn.tools

import Signature._

class Signature(val name: String, val epOnly: Boolean, val signature: Array[Option[Byte]]) {

  override def toString(): String =
    s"""|name: $name
    	|signature: ${bytes2hex(signature, " ")}
	    |ep_only: $epOnly """.stripMargin

}

object Signature {
  
  /**
   * Converts an array of Option bytes to its hex string representation. None is
   * converted to "??"
   * 
   * @param bytes byte array to be converted
   * @param sep the character(s) that separates to bytes in the string
   * @return
   */
  def bytes2hex(bytes: Array[Option[Byte]], sep: String): String = {
    bytes.foldLeft("")((s, b) => b match {
      case None => s + sep + "??"
      case _ => s + sep + "%02x".format(b.get)
    })
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