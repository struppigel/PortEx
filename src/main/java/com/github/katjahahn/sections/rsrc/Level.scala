package com.github.katjahahn.sections.rsrc

import Level._

class Level(val levelNr: Int) extends Equals {

  override def toString(): String = 
    "level: " + levelDescription.getOrElse(levelNr, levelNr.toString)

  def up(): Level = new Level(levelNr + 1)

  def canEqual(other: Any) = {
    other.isInstanceOf[Level]
  }

  override def equals(other: Any) = {
    other match {
      case that: Level => that.canEqual(Level.this) && levelNr == that.levelNr
      case _ => false
    }
  }

  override def hashCode() = {
    val prime = 41
    prime + levelNr.hashCode
  }

}

object Level {
  
  private val levelDescription = Map(1 -> "type", 2 -> "name", 3 -> "language")

  def apply(): Level = new Level(1)
}