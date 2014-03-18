package com.github.katjahahn.tools.sigscanner

import scala.collection.mutable.MutableList
import PartialFunction._

/**
 * A mutable prefix tree for byte signatures. Provides a fast way to match a byte
 * sequence to a large number of signatures
 *
 * @author Katja Hahn
 *
 */
abstract class SignatureTree {

  /**
   * Inserts the signature to the tree. Note that the SignatureTree is mutable
   *
   * @param sig signature to be inserted
   * @return tree with new signature
   */
  def +(sig: Signature): SignatureTree = {
    insert(sig, sig.signature.toList)
    this
  }

  /**
   * @param sig the signature to be inserted
   * @param bytes the byte sequence that has to be inserted to the rest of the
   *        tree
   */
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

  /**
   * Collects all signatures that match the given byte sequence.
   *
   * @param bytes the byte sequence to compare with the signatures
   * @return list of signatures that matches the bytes
   */
  def findMatches(bytes: List[Byte]): List[Signature] = {
    bytes match {

      case b :: bs => this match {
        case Node(c, v) =>
          val children = c.filter(_.matchesValue(b))
          children.foldRight(List[Signature]())(
            (ch, l) => ch.findMatches(bs) ::: l) ::: collectSignatures(c)
        case Leaf(s) => List(s)
      }

      case Nil => this match {
      	case Node(c, v) => collectSignatures(c)
        case Leaf(s) => List(s)
      }
    }
  }

  /**
   * Collects the signatures of all leaves in the given list.
   * Actually there should only be one signature in one childrenlist, otherwise
   * you have two signatures with the same byte sequence.
   *
   * @param list a list that contains nodes and leaves
   * @return all signatures found in the leaves of the list
   */
  private def collectSignatures(list: MutableList[SignatureTree]): List[Signature] = {
    list.collect({ case Leaf(s) => s }).toList
  }

  /**
   * Returns whether the current SignatureTree Node (or Leave) has a value that equals b.
   *  A Leave always returns false as it has no value saved.
   *
   * @param b an Option byte
   * @return true iff it is a Node and has a value that equals b
   */
  protected def hasValue(b: Option[Byte]): Boolean = false

  /**
   * Returns whether the current SignatureTree Node (or Leave) has a value that
   * matches b (Note: None matches to every Byte).
   * A Leave always returns false as it has no value saved.
   * 
   * @param b a Byte
   * @return true if the given byte matches the value in the node; that means 
   * if the value in the node is a None, it returns true; if the current node is
   * a Leave it returns false
   */
  protected def matchesValue(b: Byte): Boolean = false

}

private case class Node(children: MutableList[SignatureTree], value: Option[Byte]) extends SignatureTree {

  override protected def hasValue(b: Option[Byte]): Boolean = value == b

  override protected def matchesValue(b: Byte): Boolean = value match {
    case None => true
    case Some(v) => v == b
  }
  override def toString(): String = value + "[" + children.mkString(",") + "]"
}

private case class Leaf(signature: Signature) extends SignatureTree {
  override def toString(): String = signature.name
}

object SignatureTree {

  /**
   * Creates an empty SignatureTree
   */
  def apply(): SignatureTree = Node(MutableList[SignatureTree](), null)

  def main(args: Array[String]): Unit = {
    val tree = SignatureTree()
    val bytes = List(Some(1.toByte), None, Some(3.toByte), Some(4.toByte))
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
    println(tree.findMatches(List(1, 2, 3).map(_.toByte)))
  }

}