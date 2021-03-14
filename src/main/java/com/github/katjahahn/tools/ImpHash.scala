/**
 * *****************************************************************************
 * Copyright 2021 Karsten Philipp Boris Hahn
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
package com.github.katjahahn.tools

import com.github.katjahahn.parser.PELoader
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.idata.ImportDLL

import java.io.File
import java.security.MessageDigest
import scala.collection.JavaConverters._

/**
 * Tool to calculate the imphash of a PE file
 * Based on https://github.com/erocarrera/pefile/blob/master/pefile.py
 * First mention of imphash in:
 * https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html
 *
 * Example code:
 * <pre>
 * {@code
 * File file = new File("WinRar.exe");
 * String imphash = ImpHash.calculate(file);
 * System.out.println(imphash);
 * </pre>
 *
 * @author Karsten Philipp Boris Hahn
 */
object ImpHash extends App {

  /**
   * Calculate the Imphash for the given PE file
   * TODO test case
   * TODO add ordinal import db
   * @param file a Portable Executable
   * @return Imphash as string
   */
  def calculate(file: File): String = {
    // loading imports iff valid PE and import section
    val data = PELoader.loadPE(file)
    val loader = new SectionLoader(data)
    val maybeIdata = loader.maybeLoadImportSection()
    if(!maybeIdata.isPresent) throw new Exception("No imports!")
    val idata = maybeIdata.get()
    // construct import string
    val imports = idata.getImports().asScala
    val impstring = constructImportString(imports.toList)
    println(impstring)
    md5String(impstring)
  }

  /**
   * Create import string based on pefile algorithm
   * moduleNames are stripped from certain extensions
   * module and function name are concatenated with dot and lowercased
   * @param imports in order
   * @return import string
   */
  private def constructImportString(imports: List[ImportDLL]): String = {
    {
      for (impDLL <- imports) yield {
        val moduleName = stripExtension(impDLL.getName)
        val namedImps = impDLL.getNameImports.asScala
        val ordImps = impDLL.getOrdinalImports.asScala
        // TODO order of namedImps and ordImps may differ in pefile, look for testfile with several ord entries
        namedImps.map(moduleName + "." + _.getName).mkString(",") + ordImps.map(moduleName + ".ord" + _.getOrdinal).mkString(",")
      }
    }.mkString(",").toLowerCase
  }

  /**
   * Strip string from extensions .ocx, .sys, or .dll as done in
   * https://github.com/erocarrera/pefile/blob/master/pefile.py
   * @param moduleName
   * @return string without any of the extensions
   */
  private def stripExtension(moduleName : String): String = {
    val extensions = List(".ocx", ".sys", ".dll")
    require(extensions.forall(_.length == 4))
    if (extensions.exists(moduleName.toLowerCase.endsWith))
      moduleName.dropRight(4)
    else
      moduleName
  }

  /**
   * Calculate MD5 hash for the string and convert to hex string representation
   * @param text
   * @return hex string of md5 hash
   */
  private def md5String(text: String) : String = {
    md5(text).map(0xFF & _).map { "%02x".format(_) }.foldLeft(""){_ + _}
  }

  /**
   * Calculate MD5 hash of the string
   * @param text
   * @return MD5 hash as byte array
   */
  private def md5(text: String) : Array[Byte] = {
    MessageDigest.getInstance("MD5").digest(text.getBytes)
  }
}
