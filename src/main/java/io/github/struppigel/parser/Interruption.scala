/**
 * *****************************************************************************
 * Copyright 2026 Karsten Hahn
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
package io.github.struppigel.parser

/**
 * Thrown when a PE analysis is aborted because the executing thread was
 * interrupted, e.g. via `Thread.interrupt()` by an embedding application
 * that wants to cancel a long running analysis.
 * <p>
 * The thread's interrupt flag is intentionally left set when this exception
 * is thrown, so that enclosing code that accidentally swallows the exception
 * still aborts at the next interruption checkpoint.
 * <p>
 * A `PEData` instance whose computation was aborted by this exception may
 * hold partially computed state and should be discarded.
 */
class AnalysisInterruptedException(message: String) extends RuntimeException(message) {
  def this() = this("PE analysis aborted because the thread was interrupted")
}

/**
 * Cooperative cancellation support for long running analysis loops.
 * <p>
 * Long running loops (full file scans, entropy calculation, per-entry
 * parsing of attacker controlled structures) call `checkInterrupt()` once
 * per chunk/entry/iteration. Blocking calls that throw
 * `InterruptedException` must restore the interrupt flag with
 * `Thread.currentThread().interrupt()` and then throw
 * [[AnalysisInterruptedException]].
 * <p>
 * Callable from Java as `Interruption.checkInterrupt()`.
 */
object Interruption {

  /**
   * Throws [[AnalysisInterruptedException]] if the current thread has been
   * interrupted. Never clears the interrupt flag (uses `isInterrupted`, not
   * `Thread.interrupted()`), so repeated checks keep firing even if an
   * intermediate catch block discards the exception.
   */
  @inline def checkInterrupt(): Unit =
    if (Thread.currentThread().isInterrupted)
      throw new AnalysisInterruptedException()
}
