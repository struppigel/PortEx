/*******************************************************************************
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
 ******************************************************************************/
package io.github.struppigel.tools.anomalies

import io.github.struppigel.parser.PEData

/**
 * Looks for certain anomalies in the given data parameter
 */
abstract class AnomalyScanner(val data: PEData) {
  
  /**
   * Returns a report of the anomaly scan
   * 
   * @return a scan report
   */
  def scanReport(): String

  /**
   * Scans for anomalies and returns a list of anomalies found.
   * 
   * @return anomaly list
   */
  def scan(): List[Anomaly]
  
}
