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
    val probs = subtypes.map(subtype => probabilities(subtype))
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
    val folder = new File("/home/deque/virusshare128/pe")
    val threshhold = 0.90
    var malcounter = 0
    var total = 0
    for (file <- folder.listFiles()) {
      try {
        val p = DetectionHeuristic(file).malwareProbability
        val malicious = p > threshhold
        total += 1
        malcounter += 1
        if(total % 1000 == 0) {
          println("files read: " + total)
          println("malicious: " + malcounter)
        }
      }catch{
        case e: Exception => System.err.println(e.getMessage());
      }
    }
    println("total: " + total)
    println("malicious: " + malcounter)
    println("detection ratio: " + (total / malcounter.toDouble))
  }

  def apply(file: File): DetectionHeuristic = {
    val data = PELoader.loadPE(file)
    val scanner = PEAnomalyScanner.newInstance(data)
    val list = scanner.getAnomalies.asScala.toList
    val probabilities = readProbabilities()
    new DetectionHeuristic(list, probabilities)
  }

  private def readProbabilities(): Map[AnomalySubType, AnomalyProb] = {
    val malprobs = IOUtil.readMap("malwareanomalystats").asScala.toMap
    val goodprobs = IOUtil.readMap("goodwareanomalystats").asScala.toMap
    malprobs map tupled { (key, arr) =>
      val subtype = AnomalySubType.valueOf(key)
      val malicious = arr(1).toDouble
      val good = goodprobs.getOrElse(key, Array("", "0.5"))(1).toDouble
      val prob = AnomalyProb(malicious, good)
      (subtype, prob)
    }
  }

}