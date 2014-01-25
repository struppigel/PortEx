package com.github.katjahahn.tools

import scala.collection.mutable.MutableList
import PartialFunction._

abstract class SigTree {

  //TODO semantics? return a copy
  def +(sig: Signature): SigTree = {
    insert(sig, sig.signature.toList)
    this
  }

  private def insert(sig: Signature, bytes: List[Option[Byte]]): Unit = {
    bytes match {
      case b :: bs => this match {
        case Node(c, v) =>
          val op = c.find(_.hasValue(b))
          val node = op.getOrElse { val n = Node(MutableList(), b); c += n; n }
          node.insert(sig, bs)
        case _ => throw new IllegalStateException("wrong tree component")
      }

      case Nil =>
        this match {
          case Node(c, v) => c += Leaf(sig)
          case _ => throw new IllegalStateException("wrong tree component")
        }
    }
  }

  def findMatches(bytes: List[Byte]): List[Signature] = {
    bytes match {

      case b :: bs => this match {
        case Node(c, v) => c.find(_.matchesValue(b)) match {
          case Some(ch) => ch.findMatches(bs) ::: getLeafSig(c)
          case None => getLeafSig(c)
        }

        case Leaf(s) => List(s)
      }

      case Nil => this match {
        case Leaf(s) => List(s)
        case Node(c, v) => getLeafSig(c)
      }
    }
  }

  private def getLeafSig(list: MutableList[SigTree]): List[Signature] = {
    val op = list.find(cond(_){ case Leaf(s) => true })
    op match {
      case None => Nil
      case Some(leaf) => leaf match { case Leaf(s) => List(s); case _ => Nil }
    }
  }

  protected def hasValue(b: Option[Byte]): Boolean = false
  protected def matchesValue(b: Byte): Boolean = false

}

case class Node(children: MutableList[SigTree], value: Option[Byte]) extends SigTree {

  override protected def hasValue(b: Option[Byte]): Boolean = value == b

  override protected def matchesValue(b: Byte): Boolean = value match {
    case None => true
    case Some(v) => v == b
  }
  override def toString(): String = value + "[" + children.mkString(",") + "]"
}

case class Leaf(signature: Signature) extends SigTree {
  override def toString(): String = signature.name
}

object SigTree {

  def apply(): SigTree = Node(MutableList[SigTree](), null)

  def main(args: Array[String]): Unit = {
    val tree = SigTree()
    val bytes = List(1, 2, 3, 4).map(x => Some(x.toByte))
    val bytes2 = List(1, 2, 3).map(x => Some(x.toByte))
    val bytes3 = List(6, 7, 8).map(x => Some(x.toByte))
    val sig = new Signature("first", false, bytes.toArray)
    val sig2 = new Signature("second", false, bytes2.toArray)
    val sig3 = new Signature("third", true, bytes3.toArray)
    tree + sig
    tree + sig2
    tree + sig3
    println()
    println(tree)
    println(tree.findMatches(List(1, 2, 3, 4).map(_.toByte)))
  }

}