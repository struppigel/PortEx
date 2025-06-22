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
package io.github.struppigel.tools.rehints

import io.github.struppigel.parser.IOUtil.NL
import io.github.struppigel.parser.PhysicalLocation
import io.github.struppigel.tools.anomalies.Anomaly

import scala.collection.JavaConverters._

/**
 * An ReHint represents a collection of anomalies that led to giving a certain advice on how to analyse the file
 */
abstract class ReHint() {

  override def toString: String = description() + NL + "\t* " + anomalies().asScala.mkString(NL+ "\t* ") + NL

  /**
   * List of anomalies that led to the ReHint
   * @return
   */
  def anomalies(): java.util.List[Anomaly]

  /**
   * The description of the rehint, this is the advice that the ReHint provides
   */
  def description(): String = reType().getDescription()

  /**
   * Returns a list of all locations relevant for the rehint, these are usually the location lists of all anomalies
   */
  def locations(): java.util.List[PhysicalLocation] = anomalies().asScala.flatMap(_.locations().asScala).asJava

  /**
   * The type of ReHint
   * @return
   */
  def reType(): ReHintType

  /**
   * List of descriptions listing all the reasons of why this rehint was given.
   * This is usually the description of every anomaly
   * @return
   */
  def reasons(): java.util.List[String] = anomalies().asScala.map(_.description()).asJava

}

/**
 * Several anomalies led to the ReHint
 *
 * @param anomalies
 * @param reType
 */
case class StandardReHint(override val anomalies: java.util.List[Anomaly], override val reType: ReHintType) extends ReHint {}

/**
 * One anomaly led to the ReHint
 *
 * @param anomaly
 * @param reType
 */
case class SimpleReHint(val anomaly: Anomaly, override val reType: ReHintType) extends ReHint {
  def anomalies(): java.util.List[Anomaly] = List(anomaly).asJava
}