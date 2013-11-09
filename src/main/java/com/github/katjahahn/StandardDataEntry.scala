package com.github.katjahahn

import scala.collection.mutable.ListBuffer
import scala.collection.JavaConverters._
import com.github.katjahahn.PEModule._

class StandardDataEntry[K <: Enumeration] (
  private val entrybytes: Array[Byte],
  private val specLocation: String
		) extends PEModule {
  
  private val specification = FileIO.readMap(specLocation).asScala.toMap
  
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
 
  def apply(key: K#Value): Int = {
    entries.find(x => x.key == key.toString) match {
      case Some(e) => e.value 
      case None => throw new IllegalArgumentException
    }
  }
  
  override def getInfo(): String = entries.mkString(NL)
  
  override def toString(): String = getInfo()

}