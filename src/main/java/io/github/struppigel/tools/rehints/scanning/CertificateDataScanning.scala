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
package io.github.struppigel.tools.rehints.scanning

import io.github.struppigel.parser.IOUtil.NL
import io.github.struppigel.tools.anomalies.AnomalySubType
import io.github.struppigel.tools.anomalies.AnomalySubType._
import io.github.struppigel.tools.rehints.{ReHint, ReHintScanner, ReHintType, StandardReHint}

import scala.collection.JavaConverters._

/**
 * Advises to dump the certificate table if data is stuffed into it: after the
 * PKCS#7 structure, into the padding or extra entries, or into unauthenticated
 * attributes and elements of the signature that its format does not define.
 */
trait CertificateDataScanning extends ReHintScanner {

  abstract override def scanReport(): String =
    "Applied CertificateDataScanning" + NL + super.scanReport

  abstract override def scan(): List[ReHint] = {
    val stuffed = anomalies.asScala.filter(a => CertificateDataScanning.stuffedDataTypes.contains(a.subtype())).toList
    val hint = if (stuffed.isEmpty) Nil else List(StandardReHint(stuffed.asJava, ReHintType.CERTIFICATE_DATA_RE_HINT))
    super.scan ::: hint
  }
}

object CertificateDataScanning {

  /**
   * Anomalies of data in the certificate table outside of the signature
   * structures. Large unauthenticated attributes are no reason on their own,
   * because nested signatures are often large, and the content of nested
   * signatures and timestamps is parsed and checked for these anomalies.
   */
  val stuffedDataTypes: Set[AnomalySubType] = Set(CERT_DATA_AFTER_PKCS7, CERT_NONZERO_PADDING, CERT_TABLE_EXTRA_DATA,
    CERT_MULTIPLE_ENTRIES, CERT_UNKNOWN_UNAUTH_ATTRIBUTE, CERT_UNEXPECTED_UNAUTH_ATTRIBUTE, CERT_EXTRA_SIGNATURE_ELEMENT)
}
