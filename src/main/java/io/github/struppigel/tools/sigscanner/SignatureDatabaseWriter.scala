/**
 * *****************************************************************************
 * Copyright 2026 Karsten Philipp Boris Hahn
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
package io.github.struppigel.tools.sigscanner

import java.io.Writer
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer

/**
 * Writes signatures in the database format, so that parsing the output yields
 * the same signatures.
 */
object SignatureDatabaseWriter {

  /**
   * Writes all signatures, each followed by a blank line.
   */
  def write(db: SignatureDatabase, out: Writer): Unit = write(db, out, Nil)

  /**
   * Writes all signatures, each followed by a blank line.
   *
   * @param header comment lines written at the top, without comment character
   */
  def write(db: SignatureDatabase, out: Writer, header: java.util.List[String]): Unit =
    write(db, out, header.asScala.toList)

  /**
   * Writes all signatures, each followed by a blank line.
   *
   * @param header comment lines written at the top, without comment character
   */
  def write(db: SignatureDatabase, out: Writer, header: Seq[String]): Unit = {
    val nl = "\n"
    header.foreach(h => out.write(if (h.isEmpty) ";" + nl else "; " + h + nl))
    if (header.nonEmpty) out.write(nl)
    for (sig <- db.signatures) {
      out.write(canonical(sig, nl))
      out.write(nl)
    }
    out.flush()
  }

  /** the database text of the signature */
  def canonical(sig: Signature, nl: String = "\n"): String = {
    val lines = ListBuffer[String]("[" + sig.name + "]")
    for (clause <- sig.clauses) {
      val suffix = if (clause.number == 1) "" else "." + clause.number
      lines += s"pattern$suffix = ${clause.pattern.source}"
      // keep the database order of the locations, grouped by at and in
      val (searches, anchors) = clause.locations.partition(_.mode.isInstanceOf[Search])
      if (anchors.nonEmpty) lines += s"at$suffix = ${anchors.map(_.source).mkString(", ")}"
      if (searches.nonEmpty) lines += s"in$suffix = ${searches.map(_.source).mkString(", ")}"
    }
    for (c <- sig.conditions) lines += s"${c.fullKey} = ${c.source}"
    for ((k, v) <- sig.metadata) lines += s"$k = $v"
    lines.mkString("", nl, nl)
  }
}
