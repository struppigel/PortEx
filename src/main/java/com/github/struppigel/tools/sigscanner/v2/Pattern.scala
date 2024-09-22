package com.github.struppigel.tools.sigscanner.v2
/*******************************************************************************
 * Copyright 2024 Karsten Hahn
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
 ******************************************************************************/
import com.github.struppigel.tools.sigscanner.v2.PatternParser.PExpression

import scala.math

class Pattern(val pieces : List[PatternElement]) {

  override def toString(): String = pieces.mkString(" ")

  def minMatchLength(): Int = pieces.map(_.minMatchLength).sum

  def matches(bytes : Array[Byte]) : Boolean = matches(bytes.toList)

  def matches(bytes : List[Byte]) : Boolean = {
    if(pieces.length == 0) return true
    else if(pieces.head.matches(bytes)) return pieces.head.matchRemains(bytes).exists(new Pattern(pieces.tail).matches(_)) || pieces.tail == Nil
    else return false

  }

  def matchRemains(bytes: List[Byte]) : List[List[Byte]] = {
    if(pieces.length == 0) return List(bytes)
    else if(pieces.head.matches(bytes))
      return pieces.head.matchRemains(bytes).filter(new Pattern(pieces.tail).matches(_))
    else return Nil
  }
}

abstract class PatternElement {
  // matches the next byte(s)
  def matches(bytes: List[Byte]) : Boolean
  // return all remaining lists for all match options
  def matchRemains(bytes: List[Byte]) : List[List[Byte]]  =
    if(bytes.length > 1) List(bytes.tail)
    else Nil
  // the required number of bytes that is necessary to match, usually it is 1
  def minMatchLength(): Int = 1
}

// CA $$ $$ $$ $$ FE BA BE TODO: Implement
// case class JumpAddress(address: Long) extends PatternElement

// CA FE ( 01 | 00 ) BA BE
// consists of pattern list
case class POption(left : PExpression, right : PExpression ) extends PatternElement {
  override def toString(): String = "(" + left.mkString(" ") + "|" + right.mkString(" ") + ")"
  override def matches(bytes: List[Byte]) : Boolean = new Pattern(left).matches(bytes) || new Pattern(right).matches(bytes)
  override def matchRemains(bytes: List[Byte]) : List[List[Byte]] =
    new Pattern(left).matchRemains(bytes) ::: new Pattern(right).matchRemains(bytes)
  override def minMatchLength(): Int = math.min(left.map(_.minMatchLength()).min, right.map(_.minMatchLength()).min)
}

case class LeftWildcardPByte(byte : Byte) extends PatternElement {
  override def toString(): String = "?" + f"$byte%01X"
  override def matches(bytes: List[Byte]) : Boolean =
    if(bytes.length == 0) false
    else (bytes.head & 0x0F) == byte
}

case class RightWildcardPByte(byte : Byte) extends PatternElement {
  override def toString(): String = f"$byte%01X" + "?"
  override def matches(bytes: List[Byte]) : Boolean =
    if(bytes.length == 0) false
    else (bytes.head & 0xF0) == byte
}

// CA FE ?? BA BE
case class WildCard() extends PatternElement {
  override def toString(): String = "??"
  override def matches(bytes: List[Byte]) : Boolean = true
}

// CA [2-10] FE BA BE
case class LimitedRange(start : Int, end : Int) extends PatternElement {
  if(start > end) throw new ParserException("Invalid range, start must be <= end")
  override def toString(): String = "[" + start + "-" + end + "]"
  override def matches(bytes: List[Byte]) : Boolean = bytes.length >= start
  override def matchRemains(bytes: List[Byte]) : List[List[Byte]] = {
    val limit = math.min(bytes.length, end)
    (for (i <- start to limit) yield bytes.drop(i)).toList // TODO check if to or until would be correct!
  }
  override def minMatchLength(): Int = start
}

// CA [2-] FE BA BE
case class BoundlessRange(start : Int) extends PatternElement {
  override def toString(): String = "[" + start + "-EOF]"
  override def matches(bytes: List[Byte]) : Boolean = bytes.length >= start
  override def matchRemains(bytes: List[Byte]) : List[List[Byte]] =
    (for (i <- start to bytes.length) yield bytes.drop(i)).toList
  override def minMatchLength(): Int = start
}

// CA
case class PByte(byte: Byte) extends PatternElement {
  override def toString(): String = f"$byte%02X"
  override def matches(bytes: List[Byte]) : Boolean =
    if(bytes.length == 0) return false
    else return byte == bytes.head

}

class ParserException(msg : String) extends Exception(msg)

object PatternParser {

  type PExpression = List[PatternElement]

  def isNibble(c: Char): Boolean = {
    c.isDigit || (c >= 'A' && c <= 'F')
  }

  def parseDecimal(patternString: String) : (String, Int) = {
    val digitString = patternString.takeWhile(_.isDigit)
    val num = Integer.parseInt(digitString)
    val rest = patternString.substring(digitString.length)
    (rest, num)
  }

  // cases, at this point the start range has been determined
  // 1: [3-12] start=3, end=12  --> -12], lastDecimal=3=start
  // 2: [3]    start=3, end=3   --> ],    lastDecimal=3=start=end
  // 3: [3-]   start=3, end=EOF --> -],   lastDecimal=3=start
  // 4: [-12]  start=0, end=12  --> -12], lastDecimal=0=start --> same as case 1
  def parseRangeEnd(patternString: String, start: Int) : PExpression = {
    if (patternString.isEmpty) throw new ParserException("Range ended prematurely")
    val head = patternString.head
    val tail = patternString.tail
    head match {
      // case 2
      case ']' => return LimitedRange(start, start) :: parse(tail)
      // case 1 and 3
      case '-' =>
        // case 1
        if(tail.isEmpty) throw new ParserException("Range ended prematurely")
        if(tail.head.isDigit) {
          val (rest, end) = parseDecimal(tail);
          if (rest.head == ']') return LimitedRange(start, end) :: parse(rest.tail)
          else throw new ParserException("No ] found for Range")
        // case 3
        } else if (tail.head == ']')
          return BoundlessRange(start) :: parse(tail.tail)
        else throw new ParserException("invalid symbol in range " + tail.head)
      case _ => throw new ParserException("invalid symbol in range " + head)
    }
  }

  // cases --> at this point '[' is already cut off
  // 1. [3-12] start=3, end=12 --> 3-12] --> '3' :: parseEnd('-12]')
  // 2. [3] start=3, end=3     --> 3]    --> '3' :: parseEnd(']')
  // 3. [3-] start=3, end=EOF  --> 3-]   --> '3' :: parseEnd('-]')
  // 4. [-12] start=0, end=12  --> -12]  --> '0' :: parseEnd('-12]')
  def parseRangeStart(patternString: String): PExpression = {
    if (patternString.isEmpty) throw new ParserException("Range ended prematurely")
    val head = patternString.head
    if ( head.isDigit ) {
      val (rest, num) = parseDecimal(patternString)
      return parseRangeEnd(rest, num)
    }
    else head match {
      case '-' => return parseRangeEnd(patternString, start=0)
      case c => throw new ParserException("invalid character in wildcard range '" + c + "'")
    }
  }

  def parsePOption(patternString : String): PExpression = {
    if (patternString.isEmpty) return Nil
    val leftExpression = patternString.takeWhile(c => c != '|' && c != ')')
    val rightExpression = patternString.substring(leftExpression.length).takeWhile(_ != ')') + ')'
    val afterOptionExpression = patternString.dropWhile(_ != ')').tail

    if (rightExpression.isEmpty) throw new ParserException("Option ends prematurely")
    rightExpression.head match {
      case '|' => return POption( parse(leftExpression), parsePOption(rightExpression.tail) ) :: parse(afterOptionExpression)
      case ')' => return parse(leftExpression) ::: parse(afterOptionExpression)
      case _ => throw new ParserException("invalid character in Option: '" + rightExpression.head + "'")
    }
  }

  def parse(patternString : String): PExpression = {
    if (patternString.isEmpty) return Nil
    val head = patternString.head
    val tail = patternString.tail
    if(tail.isEmpty) throw new ParserException("Half byte detected")
    head match {
      // Wildcard
      case '?' => {
        tail.head match {
          case '?' => return WildCard() :: parse(tail.tail)
          // Half Wildcard left
          case _ => {
            if( isNibble(tail.head) ) return LeftWildcardPByte(Integer.parseInt(tail.head.toString(), 16).toByte) :: parse(tail.tail)
            else throw new ParserException("Invalid symbol at " + tail.head)
          }
        }
      }
      // Range
      case '[' => return parseRangeStart(tail)
      // Option
      case '(' => return parsePOption(tail)
      // Other
      case _ => {
        // PByte
        if (isNibble(head) && isNibble(tail.head)) {
          val byteString = head.toString + tail.head.toString
          val byteVal = Integer.parseInt(byteString, 16).toByte
          return PByte(byteVal) :: parse(tail.tail)
        }
        // Half Wildcard right
        else if (isNibble(head) && tail.head == '?') {
          return RightWildcardPByte(Integer.parseInt(head.toString(), 16).toByte)  :: parse(tail.tail)
        }
        else throw new ParserException("Invalid symbol '" + head + tail.head + "'")
      }
    }
  }

  def parseInit(patternString : String): Pattern = {
    // remove all whitespace, and turn to upper case before parsing
    val prepped = patternString.replaceAll("\\s", "").toUpperCase()
    new Pattern(parse(prepped))
  }
}


object TestThisApp {
  def main(args: Array[String]): Unit = {
    // test case 1
    val input = "CA F? ( CA | ?F BA | CA ?? 11 [1-2] BE ) ba?? b? ?? BABE ?B (AB | BB | BC | CD | EF)"
    val pattern = PatternParser.parseInit(input)
    println(pattern)

    // test case 2
    //val bytes = List[Byte](1,2,3,4)
    //val input = "01 02 03 04"
    //val pattern = PatternParser.parseInit(input)
    //println("input: " + input)
    //println("parsed: " + pattern)
    //println("matches: " + pattern.matches(bytes))
    //// test case 2
    //val bytes = List[Byte](1,2,3,4)
    //val input = "01 02 (?? 04 | 04)"
    //val pattern = PatternParser.parseInit(input)

    // test case 3
   // val bytes = List[Byte](1,2,3,4, 5, 6, 7, 8, 9, 10)
   // val input = "01 02 03 04 05 [3-] 08 09 0A"
    //val pattern = PatternParser.parseInit(input)
    //println("input: " + input)
    //println("parsed: " + pattern)
   // println("matches: " + pattern.matches(bytes))
  }
}