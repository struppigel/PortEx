/**
 * *****************************************************************************
 * Copyright 2014 Katja Hahn
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
package com.github.katjahahn.tools

import com.github.katjahahn.parser.{FileFormatException, IOUtil, PELoader, PESignature}
import com.github.katjahahn.tools.FileScoring._
import com.github.katjahahn.tools.anomalies.{Anomaly, AnomalySubType, PEAnomalyScanner}

import java.io.File
import scala.Function.tupled
import scala.collection.JavaConverters._

/**
 * Provides file scoring based on statistical information about PE files.
 * Only anomaly statistics are used at present.
 *
 * @author Katja Hahn
 */
class FileScoring(
  private val anomalies: List[Anomaly],
  private val probabilities: Map[AnomalySubType, AnomalyProb],
  private val boosterScores: Map[AnomalySubType, BScore]) {

  /**
   * @Beta
   */
  private def isClassifyable(): Boolean = {
    // obtain number of all cleaned anomalies that have been found in the present file
    val anomalyNrThreshold = 5
    val scoringThreshold = 5.0
    val cleaned = anomalies.filter(a => probabilities.keys.toList.contains(a.subtype))
    /*cleaned.size >= anomalyNrThreshold &&*/ Math.abs(fileScore) >= scoringThreshold
  }

  /**
   * Calculates a file score based on anomalies and their BScores.
   * The higher the score, the more likely we have a malicious file.
   * A negative score indicates a non-malicious file.
   * A positive score indicates a malicious file.
   * A score of zero means there is no information whatsoever.
   * @Beta
   * @return the file's score based on its anomalies
   */
  def fileScore(): Double = {
    // obtain a set of all anomaly subtypes that have been found in the present file
    val subtypes = anomalies.map(a => a.subtype).distinct
    // obtain a list of all bscores for the subtypes found in the file
    val bscores = subtypes.map(subtype => boosterScores.get(subtype)).flatten
    // calculate and return the overall score of the file
    bscores.sum
  }

  def scoreParts(): java.util.Map[AnomalySubType, BScore] = _scoreParts().asJava

  def _scoreParts(): Map[AnomalySubType, BScore] = {
    // obtain a set of all anomaly subtypes that have been found in the present file
    val subtypes = anomalies.map(a => a.subtype).distinct
    // obtain a list of all bscores for the subtypes found in the file
    subtypes.map { subtype =>
      if (boosterScores.contains(subtype)) {
        Some((subtype, boosterScores(subtype)))
      } else None
    }.flatten.toMap
  }

  /**
   * Calculates the probability for a file to be malicious based on the
   * anomalies found in the file.
   *
   * @return probability P(BAD|Anomalies)
   */
  def malwareProbability(): Double = {
    val subtypes = anomalies.map(a => a.subtype).distinct
    val probs = subtypes.map(subtype => probabilities.get(subtype)).flatten
    val allBad = probs.foldRight(1.0) { (p, bad) => p.bad * bad }
    val allGood = probs.foldRight(1.0) { (p, good) => p.good * good }
    val bayes = allBad * 0.5 / (allGood * 0.5 + allBad * 0.5)
    bayes
    //FIXME duphead with negative filescore but 100 % ?
    //    // first round, priors chosen by principle of indifference
    //    val (firstGoodProb, firstBadProb) = conditionalProbs(0.5, 0.5)
    //    // second round uses result of the first round as input
    //    val (goodProb, badProb) = conditionalProbs(firstGoodProb, firstBadProb)
    //    badProb
  }

  /**
   * Calculates the conditional probabilities for a file to be BAD or GOOD with
   * the condition being the anomalies found in the file. This is done using
   * Bayes' Theorem with the prior probabilities goodPrior and badPrior.
   *
   * @param goodPrior the prior for P(GOOD)
   * @param badPrior the prior for P(BAD)
   * @return probability tuple (P(GOOD | Anomalies), P(BAD | Anomalies))
   */
  private def conditionalProbs(goodPrior: Double, badPrior: Double): (Double, Double) = {
    // obtain a set of all anomaly subtypes that have been found in the present file
    val subtypes = anomalies.map(a => a.subtype).distinct
    // obtain the probabilities P(Anomaly|BAD) and P(Anomaly|GOOD) for each subtype
    val probs = subtypes.map(subtype => probabilities.get(subtype)).flatten
    // calculate the overall probability P(Anomalies | BAD) for this file
    val allBad = probs.foldRight(1.0) { (p, bad) => p.bad * bad }
    // calculate the overall probability P(Anomalies | GOOD) for this file
    val allGood = probs.foldRight(1.0) { (p, good) => p.good * good }
    // calculate P(BAD | Anomalies) using Bayes' Theorem
    val bayesBad = allBad * badPrior / (allGood * goodPrior + allBad * badPrior)
    // calculate P(GOOD | Anomalies) using Bayes' Theorem
    val bayesGood = allGood * goodPrior / (allGood * goodPrior + allBad * badPrior)
    // return the tuple
    (bayesGood, bayesBad)
  }

}

/**
 * Represents the percentage of the two file sets, good and bad, to have one or
 * several certain anomalies.
 * This is equal to P(Anomaly|BAD) and P(Anomaly|GOOD)
 */
case class AnomalyProb(bad: Double, good: Double)

object FileScoring {

  val threshold = 200
  lazy val probabilities = readProbabilities()
  lazy val boosterScores = readBoosterScores()

  private val version = """version: 0.3
    |author: Katja Hahn
    |last update: 21.Jun 2014""".stripMargin

  private val title = """MalDet v0.3
                        |-----------    
                    |Please note: 
                    |MalDet uses statistical information about file anomalies to assign a probability to a file for being malicious.
                    |A probability of 50% means there is no knowledge about the file.
                    |Files with 99% probability may still be non-malicious and vice versa for files with 1% probability.
                    |MalDet is still experimental and not a substitute for any antivirus software!
                    |MalDet is made with PortEx: https://github.com/katjahahn/PortEx
                    |""".stripMargin

  private val usage = """Usage: java -jar maldet.jar -f <pefile>
                        |       java -jar maldet.jar -d <directory>
    """.stripMargin

  private type OptionMap = scala.collection.mutable.Map[Symbol, String]
  type BScore = Double

  def main(args: Array[String]): Unit = {
    testHeuristics()
  }

  private def pad(string: String, length: Int, padStr: String): String = {
    val padding = (for (i <- string.length until length by padStr.length)
      yield padStr).mkString
    string + padding
  }

  private def percentage(value: Double): String = {
    ("%.2f" format (value * 100))
  }

  //subtype; bad; good; badprob; ratio
  private def printCleanedProbs(): Unit = {
    val keyPad = "UNINIT_DATA_CONSTRAINTS_VIOLATION ".length
    println(pad("anomaly", keyPad - 2, " ") + "| bad freq | good freq | P(bad|anomaly) | bscore ")
    println()
    probabilities.foreach { prob =>
      val badProb = prob._2.bad * 0.5 / (prob._2.good * 0.5 + prob._2.bad * 0.5)
      val bscore = boosterScores(prob._1)
      println(pad(prob._1.toString, keyPad, " ") + percentage(prob._2.bad) +
        "\t\t" + percentage(prob._2.good) + "\t\t" + percentage(badProb) + "\t\t" + bscore)
    }
  }

  private def invokeCLI(args: Array[String]): Unit = {
    val options = nextOption(scala.collection.mutable.Map(), args.toList)
    println(title)
    if (args.length == 0) {
      println(usage)
    } else if (options.contains('version)) {
      println(version)
    } else if (options.contains('inputfile)) {
      try {
        val filename = options('inputfile)
        val file = new File(filename)
        println("input file: " + filename)
        if (!file.exists()) {
          System.err.println("file doesn't exist!")
        } else {
          println("scanning file ...")
          val prob = FileScoring(file).malwareProbability
          println("malware probability: " + (prob * 100) + "%")
          println("-done-")
        }
      } catch {
        case e: Exception => System.err.println(e.getMessage())
      }
    } else if (options.contains('directory)) {
      try {
        val foldername = options('directory)
        val folder = new File(foldername)
        println("input folder: " + foldername)
        if (!folder.exists()) {
          System.err.println("folder doesn't exist!")
        } else {
          println("scanning files ...")
          for (file <- folder.listFiles()) {
            if (isPEFile(file)) {
              val prob = FileScoring(file).malwareProbability
              println(file.getName() + " malware probability: " + (prob * 100) + "%")
            } else {
              println(file.getName() + " is no PE file")
            }
          }
          println("-done-")
        }
      } catch {
        case e: Exception => System.err.println(e.getMessage())
      }

    } else {
      println(usage)
    }
  }

  private def isPEFile(file: File): Boolean = {
    !file.isDirectory() && new PESignature(file).exists()
  }

  private def nextOption(map: OptionMap, list: List[String]): OptionMap = {
    list match {
      case Nil => map
      case "-d" :: value :: tail =>
        nextOption(map += ('directory -> value), tail)
      case "-v" :: tail =>
        nextOption(map += ('version -> ""), tail)
      case "-f" :: value :: tail =>
        nextOption(map += ('inputfile -> value), tail)
      case option :: tail =>
        println("Unknown option " + option + "\n" + usage)
        sys.exit(1)
    }
  }
  private def testHeuristics(): Unit = {
    val folder = new File("/home/deque/portextestfiles/kindset")
    val probThresholds = List(0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.98, 0.99)
    val probCounter = collection.mutable.Map((probThresholds.view map ((_, 0))): _*)
    val probClassifiedCounter = collection.mutable.Map((probThresholds.view map ((_, 0))): _*)
    val bscoreThresholds = for (i <- 0 to 35) yield i.toDouble
    val bscoreCounter = collection.mutable.Map((bscoreThresholds.view map ((_, 0))): _*)
    val bscoreClassifiedCounter = collection.mutable.Map((bscoreThresholds.view map ((_, 0))): _*)
    var total = 0
    var classifyable = 0
    var notLoaded = 0
    for (file <- folder.listFiles()) {
      try {
        val scoring = FileScoring(file)
        val prob = scoring.malwareProbability
        val bscore = scoring.fileScore
        total += 1
        probThresholds.filter(prob >=).foreach { probCounter(_) += 1 }
        bscoreThresholds.filter(bscore >=).foreach { bscoreCounter(_) += 1 }
        if (scoring.isClassifyable) {
          probThresholds.filter(prob >=).foreach { probClassifiedCounter(_) += 1 }
          bscoreThresholds.filter(bscore >=).foreach { bscoreClassifiedCounter(_) += 1 }
          classifyable += 1
        }
        if (total % 1000 == 0) {
          println("files read: " + total)
          println("classifyable files: " + classifyable)
          println("probabilities: ")
          printCounts(probCounter, probClassifiedCounter, total, classifyable)
          println("bscores: ")
          printCounts(bscoreCounter, bscoreClassifiedCounter, total, classifyable)
        }
      } catch {
        case e: FileFormatException => notLoaded += 1; System.err.println("file is no PE file: " + file.getName())
        case e: Exception => notLoaded += 1; e.printStackTrace()
      }
    }
    total -= notLoaded
    println("files read: " + total)
    println("classifyable files: " + classifyable)
    println("probabilities: ")
    printCounts(probCounter, probClassifiedCounter, total, classifyable)
    println("bscores: ")
    printCounts(bscoreCounter, bscoreClassifiedCounter, total, classifyable)
  }

  private def printCounts(counter: collection.mutable.Map[Double, Int],
    classifiedCounter: collection.mutable.Map[Double, Int],
    total: Int, classifyable: Int): Unit = {
    // Scala has no mutable treemap, so we create one here, we need sorted keys
    val sorted = collection.immutable.TreeMap(counter.toArray: _*)
    sorted.foreach { tuple =>
      val (threshold, count) = tuple
      val message = s"malicious by threshold ${threshold}: ${count} ratio ${(count.toDouble / total.toDouble)}"
      println(message)
    }
    println("!!! classified only:")
    val classifiedSorted = collection.immutable.TreeMap(classifiedCounter.toArray: _*)
    classifiedSorted.foreach { tuple =>
      val (threshold, count) = tuple
      val message = s"malicious by threshold ${threshold}: ${count} ratio ${(count.toDouble / classifyable.toDouble)}"
      println(message)
    }
    println()
  }

  def newInstance(file: File): FileScoring = apply(file)

  def apply(file: File): FileScoring = {
    val data = PELoader.loadPE(file)
    val scanner = PEAnomalyScanner.newInstance(data)
    val list = scanner.getAnomalies.asScala.toList
    new FileScoring(list, probabilities, boosterScores)
  }

  private def clean(bad: Map[String, Array[String]],
    good: Map[String, Array[String]]): (Map[String, Double], Map[String, Double]) = {
    val newBad = scala.collection.mutable.Map[String, Double]()
    val newGood = scala.collection.mutable.Map[String, Double]()
    // TODO add good only values ?
    for ((key, arr) <- bad) {
      val goodArr = good.getOrElse(key, Array("0", "0.0"))
      val goodNr = goodArr(0).toInt
      val goodProb = goodArr(1).toDouble
      val badNr = arr(0).toInt
      val badProb = arr(1).toDouble
      if (goodNr + badNr >= threshold) {
        newGood += (key -> goodProb)
        newBad += (key -> badProb)
      }
    }
    (newBad.toMap, newGood.toMap)
  }

  /**
   * Reads the probability statistics files for malware and non-malicious programs.
   * Cleans the probabilities from insignificant values based on the threshold.
   */
  private def readProbabilities(): Map[AnomalySubType, AnomalyProb] = {
    val rawMalprobs = IOUtil.readMap("malwareanomalystats").asScala.toMap
    val rawGoodprobs = IOUtil.readMap("goodwareanomalystats").asScala.toMap
    val (malprobs, goodprobs) = clean(rawMalprobs, rawGoodprobs)
    (malprobs map tupled { (key: String, malicious: Double) =>
      val subtype = AnomalySubType.valueOf(key)
      val good = goodprobs.getOrElse(key, 0.5)
      val prob = AnomalyProb(malicious / 100.0, good / 100.0)
      (subtype, prob)
    }).toMap ++
      (goodprobs.filterNot(t => malprobs.contains(t._1)) map tupled { (key, good) =>
        val subtype = AnomalySubType.valueOf(key)
        val malicious = malprobs.getOrElse(key, 0.5)
        val prob = AnomalyProb(malicious / 100.0, good / 100.0)
        (subtype, prob)
      }).toMap
  }

  private def readBoosterScores(): Map[AnomalySubType, BScore] = {
    val rawMalprobs = IOUtil.readMap("malwareanomalystats").asScala.toMap
    val rawGoodprobs = IOUtil.readMap("goodwareanomalystats").asScala.toMap
    val (malprobs, goodprobs) = clean(rawMalprobs, rawGoodprobs)
    (malprobs map tupled { (key: String, malicious: Double) =>
      val subtype = AnomalySubType.valueOf(key)
      val good = goodprobs.getOrElse(key, 0.5)
      val bscore = malicious / (malicious + good) * 20 - 10
      (subtype, bscore)
    }).toMap ++
      (goodprobs.filterNot(t => malprobs.contains(t._1)) map tupled { (key, good) =>
        val subtype = AnomalySubType.valueOf(key)
        val malicious = malprobs.getOrElse(key, 0.5)
        val bscore = malicious / (malicious + good) * 20 - 10
        (subtype, bscore)
      }).toMap
  }

}