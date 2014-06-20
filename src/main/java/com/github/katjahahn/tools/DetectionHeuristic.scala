package com.github.katjahahn.tools

import com.github.katjahahn.parser.PELoader
import com.github.katjahahn.tools.anomalies.Anomaly
import java.io.File
import com.github.katjahahn.tools.anomalies.PEAnomalyScanner
import scala.collection.JavaConverters._
import com.github.katjahahn.tools.anomalies.AnomalySubType
import Function.tupled
import com.github.katjahahn.parser.IOUtil

//TODO remove dependend anomalies from /data/stats file
//TODO test this more, also ask Schönherr

class DetectionHeuristic(
  private val anomalies: List[Anomaly],
  private val probabilities: Map[AnomalySubType, AnomalyProb]) {

  def malwareProbability(): Double = {
    val subtypes = anomalies.map(a => a.subtype).distinct
    val probs = subtypes.map(subtype => probabilities.get(subtype)).flatten
    val allBad = probs.foldRight(1.0) { (p, bad) => p.bad * bad }
    val allGood = probs.foldRight(1.0) { (p, good) => p.good * good }
    val bayes = allBad * 0.5 / (allGood * 0.5 + allBad * 0.5)
    bayes
  }

}

/**
 * Represents the percentage of the two file sets, good and bad, to have one or
 * several certain anomalies.
 * This is equal to P(Anomaly|BAD) and P(Anomaly|GOOD)
 */
case class AnomalyProb(bad: Double, good: Double)

object DetectionHeuristic {

  def main(args: Array[String]): Unit = {
    val folder = new File("/home/deque/portextestfiles/goodfiles")
    val threshholdA = 0.90
    val threshholdB = 0.50
    val threshholdC = 0.75
    var malcounterA = 0
    var malcounterB = 0
    var malcounterC = 0
    var total = 0
    for (file <- folder.listFiles()) {
      try {
        val p = DetectionHeuristic(file).malwareProbability
        total += 1
        if (p > threshholdA) {
          malcounterA += 1
        }
        if (p > threshholdB) {
          malcounterB += 1
        }
        if (p > threshholdC) {
          malcounterC += 1
        }
        if (total % 1000 == 0) {
          println("files read: " + total)
          println("malicious by threshhold 0.50: " + malcounterB + " ratio " + (malcounterB.toDouble / total.toDouble))
          println("malicious by threshhold 0.75: " + malcounterC + " ratio " + (malcounterC.toDouble / total.toDouble))
          println("malicious by threshhold 0.90: " + malcounterA + " ratio " + (malcounterA.toDouble / total.toDouble))
        }
      } catch {
        case e: Exception => System.err.println(e.getMessage);
      }
    }
    println("files read: " + total)
    println("malicious by threshhold 0.50: " + malcounterB + " ratio " + (malcounterB.toDouble / total.toDouble))
    println("malicious by threshhold 0.75: " + malcounterC + " ratio " + (malcounterC.toDouble / total.toDouble))
    println("malicious by threshhold 0.90: " + malcounterA + " ratio " + (malcounterA.toDouble / total.toDouble))
  }

  def apply(file: File): DetectionHeuristic = {
    val data = PELoader.loadPE(file)
    val scanner = PEAnomalyScanner.newInstance(data)
    val list = scanner.getAnomalies.asScala.toList
    val probabilities = readProbabilities()
    new DetectionHeuristic(list, probabilities)
  }

  private def clean(bad: Map[String, Array[String]],
    good: Map[String, Array[String]]): (Map[String, Double], Map[String, Double]) = {
    val threshhold = 500
    val newBad = scala.collection.mutable.Map[String, Double]()
    val newGood = scala.collection.mutable.Map[String, Double]()
    for ((key, arr) <- bad) {
      val goodArr = good.getOrElse(key, Array("0", "0.0"))
      val goodNr = goodArr(0).toInt
      val goodProb = goodArr(1).toDouble
      val badNr = arr(0).toInt
      val badProb = arr(1).toDouble
      if (goodNr + badNr >= threshhold) {
        newGood += (key -> goodProb)
        newBad += (key -> badProb)
      }
    }
    (newBad.toMap, newGood.toMap)
  }

  private def readProbabilities(): Map[AnomalySubType, AnomalyProb] = {
    val rawMalprobs = IOUtil.readMap("malwareanomalystats").asScala.toMap
    val rawGoodprobs = IOUtil.readMap("goodwareanomalystats").asScala.toMap
    val (malprobs, goodprobs) = clean(rawMalprobs, rawGoodprobs)
    malprobs map tupled { (key: String, malicious: Double) =>
      val subtype = AnomalySubType.valueOf(key)
      val good = goodprobs.getOrElse(key, 0.5)
      val prob = AnomalyProb(malicious, good)
      (subtype, prob)
    } //TODO include goodprobs that are not in malprobs
  }

}