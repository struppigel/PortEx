/**
 * *****************************************************************************
 * Copyright 2023 Karsten Hahn
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
package com.github.katjahahn.parser.sections.debug

import com.github.katjahahn.parser.{ByteArrayUtil, PEData}
import com.github.katjahahn.parser.IOUtil.loadBytes
import com.github.katjahahn.parser.ScalaIOUtil.using
import com.github.katjahahn.parser.IOUtil.NL

import java.io.{File, RandomAccessFile}
import java.security.MessageDigest

class ReproInfo(val reproHash : Array[Byte]) {

  def getInfo() : String = NL +
    "Repro" + NL +
    "--------" + NL +
    "Repro hash: " + ByteArrayUtil.byteToHex(reproHash) + NL
}

object ReproHashCalculator {

  def calculateReproHash(pedata: PEData) : Array[Byte] = {
    val digest = MessageDigest.getInstance("SHA-256");
    val bytes : Array[Byte] = ??? //TODO
    digest.update(bytes)
    val hash = digest.digest()
    hash
  }
}

object ReproInfo {

  val reproHashSize = 0x20

  def getInstance(ptrToRaw: Long, pedata: PEData): ReproInfo = {
    apply(ptrToRaw, pedata)
  }

  def apply(ptrToRaw: Long, pedata: PEData): ReproInfo = {
    using(new RandomAccessFile(pedata.getFile, "r")) { raf =>
        val reproHash = loadBytes(ptrToRaw + 4, reproHashSize, raf)
        new ReproInfo(reproHash)
    }
  }

}
