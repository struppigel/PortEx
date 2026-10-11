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
package io.github.struppigel.tools.sigscanner.perf

import scala.collection.mutable.ArrayBuffer

/**
 * Measures the PortEx 5 scanner (legacy) and the new scanner on the same
 * workload in the same JVM. Runs are interleaved to cancel out drift, every
 * sample repeats the action until it took at least minSampleNanos, and the
 * median of the samples is compared.
 */
object PerfHarness {

  /** new/legacy ratio that is still accepted, absorbs timer, GC and CPU boost jitter */
  val MaxRatio = 1.10

  /**
   * accepted ratio for scenarios in fresh JVMs: roughly equal is fine there,
   * and process start times vary more than measurements within one JVM
   */
  val MaxFreshJvmRatio = 1.15

  final case class Result(name: String, legacyNanos: Double, newNanos: Double) {
    def ratio: Double = newNanos / legacyNanos

    def speedup: Double = legacyNanos / newNanos

    override def toString: String =
      f"$name%-58s legacy ${legacyNanos / 1e6}%10.3f ms   new ${newNanos / 1e6}%10.3f ms   ratio $ratio%6.3f   speedup $speedup%8.1fx"
  }

  private val results = ArrayBuffer[String]()

  /** prevents the JIT from removing unused results */
  @volatile var sink: Int = 0

  def consume(x: Any): Unit = sink += x.hashCode()

  /**
   * Time per action in nanoseconds, averaged over enough repetitions to
   * reach minSampleNanos. Only the action is timed, not the setup.
   */
  def sample[S](setup: () => S, action: S => Any, minSampleNanos: Long): Double = {
    var total = 0L
    var count = 0
    while (total < minSampleNanos || count == 0) {
      val s = setup()
      val start = System.nanoTime()
      consume(action(s))
      total += System.nanoTime() - start
      count += 1
    }
    total.toDouble / count
  }

  def median(values: Seq[Double]): Double = {
    val sorted = values.sorted
    if (sorted.size % 2 == 1) sorted(sorted.size / 2)
    else (sorted(sorted.size / 2 - 1) + sorted(sorted.size / 2)) / 2
  }

  /**
   * Compares legacy and new with separate setups, the setups are not timed.
   */
  def compare[L, N](name: String, warmups: Int = 5, runs: Int = 15, minSampleNanos: Long = 50000000L)(
      legacySetup: () => L, legacy: L => Any)(newSetup: () => N, current: N => Any): Result = {
    for (_ <- 0 until warmups) {
      sample(legacySetup, legacy, minSampleNanos)
      sample(newSetup, current, minSampleNanos)
    }
    val legacyTimes = ArrayBuffer[Double]()
    val newTimes = ArrayBuffer[Double]()
    for (i <- 0 until runs) {
      // ABBA order
      if (i % 2 == 0) {
        legacyTimes += sample(legacySetup, legacy, minSampleNanos)
        newTimes += sample(newSetup, current, minSampleNanos)
      } else {
        newTimes += sample(newSetup, current, minSampleNanos)
        legacyTimes += sample(legacySetup, legacy, minSampleNanos)
      }
    }
    report(Result(name, median(legacyTimes), median(newTimes)))
  }

  /** compares two actions without setup */
  def compareSimple(name: String, warmups: Int = 5, runs: Int = 15, minSampleNanos: Long = 50000000L)(
      legacy: => Any)(current: => Any): Result =
    compare(name, warmups, runs, minSampleNanos)(() => (), (_: Unit) => legacy)(() => (), (_: Unit) => current)

  def report(result: Result): Result = {
    println(result)
    results += result.toString
    result
  }

  /** a measurement without legacy counterpart */
  def reportOnly(line: String): Unit = {
    println(line)
    results += line
  }

  def summary: Seq[String] = results.toList
}
