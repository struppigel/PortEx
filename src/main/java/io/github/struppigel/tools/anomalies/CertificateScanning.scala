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
package io.github.struppigel.tools.anomalies

import io.github.struppigel.parser.IOUtil._
import io.github.struppigel.parser.optheader.{DataDirEntry, DataDirectoryKey}
import io.github.struppigel.parser.sections.cert.{CertificateIssue, CertificateIssueType}

import scala.collection.JavaConverters._

/**
 * Scans the certificate table and the Authenticode signatures for anomalies.
 * <p>
 * The issues found by the parser and the verifier are typed as described in
 * the master thesis: problems of the data directory entry and of the
 * WIN_CERTIFICATE header fields are field malformations, problems with the
 * location, ordering, amount or completeness of structures are structural
 * malformations, wrong fields of the signature are field malformations
 * (AuthenticodeAnomaly), and valid but unusual properties are non-default.
 *
 * @author Karsten Philipp Boris Hahn
 */
trait CertificateScanning extends AnomalyScanner {

  abstract override def scanReport(): String =
    "Applied Certificate Scanning" + NL + super.scanReport

  abstract override def scan(): List[Anomaly] = {
    val maybeEntry = data.getOptionalHeader.maybeGetDataDirEntry(DataDirectoryKey.CERTIFICATE_TABLE)
    val table = data.loadCertificateTable()
    val anomalies =
      if (maybeEntry.isPresent && table.isPresent) {
        val verification = data.loadAuthenticodeVerification()
        val issues = table.get.getIssues.asScala.toList ++
          (if (verification.isPresent) verification.get.getIssues.asScala.toList else Nil)
        issues.flatMap(issue => CertificateScanning.toAnomaly(issue, maybeEntry.get))
      } else Nil
    super.scan ::: anomalies
  }
}

object CertificateScanning {

  private val dataDirectoryIssues = Set(CertificateIssueType.DIR_NOT_ALIGNED,
    CertificateIssueType.DIR_SIZE_EXCEEDS_FILE, CertificateIssueType.DIR_TOO_SMALL)

  /**
   * Returns the anomaly subtype for a certificate issue type.
   *
   * @param issueType the issue type
   * @return the subtype CERT_ + issue type name, EXHAUSTIVE_DATA for exceeded
   *         limits, None for TABLE_BEYOND_EOF, which is reported as
   *         INVALID_DATA_DIR by the optional header scanning
   */
  def subtypeFor(issueType: CertificateIssueType): Option[AnomalySubType] = issueType match {
    case CertificateIssueType.TABLE_BEYOND_EOF => None
    case CertificateIssueType.LIMIT_EXCEEDED => Some(AnomalySubType.EXHAUSTIVE_DATA)
    case other => Some(AnomalySubType.valueOf("CERT_" + other.name))
  }

  /**
   * Converts a certificate issue to an anomaly.
   *
   * @param issue the issue
   * @param entry the certificate table data directory entry
   * @return the anomaly, None if the issue is reported elsewhere
   */
  def toAnomaly(issue: CertificateIssue, entry: DataDirEntry): Option[Anomaly] =
    subtypeFor(issue.getType).map { subtype =>
      val description = "Certificate Table: " + issue.getDescription
      if (dataDirectoryIssues.contains(issue.getType))
        DataDirAnomaly(entry, description, subtype)
      else if (issue.getHeaderField.isPresent)
        FieldAnomaly(issue.getHeaderField.get, description, subtype)
      else if (subtype.getSuperType == AnomalyType.STRUCTURE)
        StructureAnomaly(PEStructureKey.CERTIFICATE_TABLE, description, subtype, issue.getLocations.asScala.toList)
      else {
        val key: FieldOrStructureKey =
          if (issue.getFieldKey.isPresent) issue.getFieldKey.get else PEStructureKey.CERTIFICATE_TABLE
        AuthenticodeAnomaly(key, description, subtype, issue.getLocations)
      }
    }
}
