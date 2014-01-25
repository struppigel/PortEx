package com.github.katjahahn.tools

import Signature._

class Signature(val name: String, val epOnly: Boolean, val signature: Array[Option[Byte]]) {

  override def toString(): String =
    s"""|name: $name
    	|signature: ${bytes2hex(signature, " ")}
	    |ep_only: $epOnly """.stripMargin

}

object Signature {
  
  def bytes2hex(bytes: Array[Option[Byte]], sep: String): String = {
    bytes.foldLeft("")((s, b) => b match {
      case None => s + sep + "??"
      case _ => s + sep + "%02x".format(b.get)
    })
  }

  def hex2bytes(hex: String): Array[Option[Byte]] = {
    val arr = hex.replaceAll("[^0-9A-Fa-f?]", "").sliding(2, 2).toArray
    arr.map(str => str match {
      case "??" => None
      case _ => Some(Integer.parseInt(str, 16).toByte)
    })
  }
}