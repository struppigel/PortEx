package com.github.katjahahn.parser.sections.rsrc.version

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

}