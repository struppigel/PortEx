/**
 * *****************************************************************************
 * Copyright 2014 Karsten Philipp Boris Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ****************************************************************************
 */
package io.github.struppigel.tools.sigscanner.legacy

import scala.collection.mutable.MutableList

/**
 * Frozen copy of the PortEx 5.x (v1) prefix tree for byte signatures.
 * <p>
 * Only used as a baseline for the differential and performance tests of the
 * signature scanner. Do not change the behaviour of this class.
 */
abstract class LegacySignatureTree {

  def +(sig: LegacySignature): LegacySignatureTree = {
    insert(sig, sig.pattern.toList)
    this
  }

  private def insert(sig: LegacySignature, bytes: List[Option[Byte]]): Unit = {
    bytes match {
      case b :: bs => this match {
        case LegacyNode(c, v) =>
          val op = c.find(_.hasValue(b))
          val node = op.getOrElse { val n = LegacyNode(MutableList(), b); c += n; n }
          node.insert(sig, bs)
        case _ => throw new IllegalStateException("wrong tree component")
      }

      case Nil =>
        this match {
          case LegacyNode(c, v) => c += LegacyLeaf(sig)
          case _ => throw new IllegalStateException("wrong tree component")
        }
    }
  }

  def findMatches(bytes: List[Byte]): List[LegacySignature] = {
    bytes match {

      case b :: bs => this match {
        case LegacyNode(c, v) =>
          val children = c.filter(_.matchesValue(b))
          children.foldRight(List[LegacySignature]())(
            (ch, l) => ch.findMatches(bs) ::: l) ::: collectSignatures(c)
        case LegacyLeaf(s) => List(s)
      }

      case Nil => this match {
      	case LegacyNode(c, v) => collectSignatures(c)
        case LegacyLeaf(s) => List(s)
      }
    }
  }

  private def collectSignatures(list: MutableList[LegacySignatureTree]): List[LegacySignature] = {
    list.collect({ case LegacyLeaf(s) => s }).toList
  }

  protected def hasValue(b: Option[Byte]): Boolean = false

  protected def matchesValue(b: Byte): Boolean = false

}

private case class LegacyNode(children: MutableList[LegacySignatureTree], value: Option[Byte]) extends LegacySignatureTree {

  override protected def hasValue(b: Option[Byte]): Boolean = value == b

  override protected def matchesValue(b: Byte): Boolean = value match {
    case None => true
    case Some(v) => v == b
  }
  override def toString(): String = value + "[" + children.mkString(",") + "]"
}

private case class LegacyLeaf(signature: LegacySignature) extends LegacySignatureTree {
  override def toString(): String = signature.name
}

object LegacySignatureTree {

  def apply(): LegacySignatureTree = LegacyNode(MutableList[LegacySignatureTree](), null)

}
