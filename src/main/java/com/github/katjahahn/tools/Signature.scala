package com.github.katjahahn.tools

import Signature._

/**
 * @author Katja Hahn
 *
 * @constructor Creates a signature instance with the values specified
 *
 * @param name the name of the packer or compiler
 * @param epOnly true iff only found at the entry point of the PE file
 * @param sigmature the byte signature, where the Option None denotes unknown
 * 				    bytes ("??" in signature file)
 */
class Signature(val name: String, val epOnly: Boolean, val signature: Array[Option[Byte]]) {

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
   * Converts an array of Option bytes to its hex string representation. None is
   * converted to "??"
   *
   * @param bytes byte array to be converted
   * @param sep the character(s) that separates to bytes in the string
   * @return string that represents the byte values as hex numbers
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