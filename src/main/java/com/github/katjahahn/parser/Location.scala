package com.github.katjahahn.parser

class Location(val from: Long, val size: Long) extends Equals {

  def canMerge(that: Location): Boolean =
    this.from + this.size == that.from

  def merge(that: Location): Location =
    new Location(this.from, this.size + that.size)

  def canEqual(other: Any) = {
    other.isInstanceOf[com.github.katjahahn.parser.Location]
  }
  
  override def toString(): String = "Loc(" + from + ", " + (from + size) + ")"

  override def equals(other: Any) = {
    other match {
      case that: com.github.katjahahn.parser.Location => that.canEqual(Location.this) && from == that.from && size == that.size
      case _ => false
    }
  }

  override def hashCode() = {
    val prime = 41
    prime * (prime + from.hashCode) + size.hashCode
  }
}

object Location {

  def mergeContinuous(locs: List[Location]): List[Location] = {
    locs.foldLeft(List[Location]()) { (list, loc) =>
      if (list.isEmpty) List(loc)
      else if (list.last.canMerge(loc)) list.take(list.length - 1) :+ list.last.merge(loc)
      else list :+ loc
    }
  }
}

