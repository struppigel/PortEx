package com.github.katjahahn.parser

class VirtualLocation(from: Long, size: Long) extends Location(from, size) {
  override def merge(that: Location): Location =
    new VirtualLocation(this.from, this.size + that.size)
}

class PhysicalLocation(from: Long, size: Long) extends Location(from, size) {
  override def merge(that: Location): Location =
    new PhysicalLocation(this.from, this.size + that.size)
}

abstract class Location(val from: Long, val size: Long) extends Equals {

  def canMerge(that: Location): Boolean =
    this.getClass() == that.getClass() &&
      this.from + this.size == that.from

  def merge(that: Location): Location

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

  def mergeContinuous[T <: Location](locs: List[T]): List[T] = {
    locs.foldLeft(List[T]()) { (list, loc) =>
      if (list.isEmpty) List(loc)
      else if (list.last.canMerge(loc)) {
        list.take(list.length - 1) :+ (list.last.merge(loc).asInstanceOf[T])
      } else list :+ loc
    }
  }
}

