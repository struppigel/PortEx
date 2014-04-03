package com.github.katjahahn.sections.rsrc

class Resource(
  val resourceBytes: Array[Byte], 
  var levelIDs: Map[Level, IDOrName]) {
  
  def this(resourceBytes: Array[Byte]) = this(resourceBytes, Map.empty)
  
  override def toString(): String = levelIDs.mkString(" || ")

}