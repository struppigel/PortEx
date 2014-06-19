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
//TODO test this more (seems to work for now), also ask Schönherr

class DetectionHeuristic(
  private val anomalies: List[Anomaly],
  private val probabilities: Map[AnomalySubType, AnomalyProb]) {

  def malwareProbability(): Double = {
    val subtypes = anomalies.map(a => a.subtype).distinct
    val anProb = subtypes.foldRight(AnomalyProb(0.5, 0.5)){(t, prob) => 
      connectedProb(prob, probabilities(t))
    }
    anProb.malicious
  }
  
  private def connectedProb(cProb: AnomalyProb, dProb: AnomalyProb): AnomalyProb = {
    val malicious = connectMaliciousProb(cProb, dProb)
    val good = connectGoodProb(cProb, dProb)
    AnomalyProb(malicious, good)
  }

  private def malwareProbabilityOf(subtype: AnomalySubType): Double = {
    val cBad = probabilities(subtype).malicious
    val cGood = probabilities(subtype).good
    conditionalProbOfBForC(cBad, cGood)
  }

  private def conditionalProbOfBForC(cB: Double, cA: Double): Double = {
    val a = 0.5
    val b = 0.5
    (cB * b) / (cB * b + cA * a)
  }

  private def connectMaliciousProb(cProb: AnomalyProb, dProb: AnomalyProb): Double = {
    val cBad = cProb.malicious
    val dBad = dProb.malicious
    val cGood = cProb.good
    val dGood = dProb.good
    connectMalicousProb(cGood, cBad, dGood, dBad)
  }

  private def goodProbabilityOf(subtype: AnomalySubType): Double = {
    val cGood = probabilities(subtype).good
    val cBad = probabilities(subtype).malicious
    conditionalProbOfBForC(cGood, cBad)
  }

  private def connectGoodProb(cProb: AnomalyProb, dProb: AnomalyProb): Double = {
    val cBad = cProb.malicious
    val dBad = dProb.malicious
    val cGood = cProb.good
    val dGood = dProb.good
    connectMalicousProb(cBad, cGood, dBad, dGood)
  }

  private def connectMalicousProb(cGood: Double, cBad: Double, dGood: Double,
    dBad: Double): Double = {
    val bad = 0.5
    val good = 0.5
    val badC = (cBad * bad) / (cBad * bad + cGood * good)
    val goodC = (cGood * good) / (cGood * good + cBad * bad)
    (dBad * badC) / (dBad * badC + dGood * goodC)
  }
}

case class AnomalyProb(malicious: Double, good: Double)

object DetectionHeuristic {

  def main(args: Array[String]): Unit = {
    val p = DetectionHeuristic(new File("/home/deque/portextestfiles/launch4jexe.exe")).malwareProbability
    println("probability to be malicious: " + (p * 100) + " %")
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
    malprobs map tupled {(key, arr) => 
      val subtype = AnomalySubType.valueOf(key)
      val malicious = arr(1).toDouble
      val good = goodprobs(key)(1).toDouble
      val prob = AnomalyProb(malicious, good)
      (subtype, prob)
    }
  }

}