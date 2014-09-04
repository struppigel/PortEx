/**
 * *****************************************************************************
 * Copyright 2014 Katja Hahn
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
package com.github.katjahahn.parser

/**
 * Utilities for Scala specific IO.
 */
object ScalaIOUtil {

  def using[A, B <: { def close(): Unit }](closeable: B)(f: B => A): A =
    try { f(closeable) } finally { closeable.close() }

  def hex(value: Long): String = "0x" + java.lang.Long.toHexString(value)

  /**
   * Fills an array with 0 bytes of the size
   */
  def zeroBytes(size: Int): Array[Byte] =
    if (size >= 0) {
      Array.fill(size)(0.toByte)
    } else Array()

}