package com.github.katjahahn.tools

import com.github.katjahahn.parser.PELoader
import com.github.katjahahn.tools.anomalies.Anomaly
import java.io.File
import com.github.katjahahn.tools.anomalies.PEAnomalyScanner
import scala.collection.JavaConverters._
import com.github.katjahahn.tools.anomalies.AnomalySubType
import Function.tupled
import com.github.katjahahn.parser.IOUtil
import scala.None
import scala.None
import scala.None
import com.github.katjahahn.parser.PESignature

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

  val threshhold = 500
  lazy val probabilities = readProbabilities()

  private val version = """version: 0.1
    |author: Katja Hahn
    |last update: 20.Jun 2014""".stripMargin

  private val title = """MalDet v0.1
                        |-----------    
                    |Please note: 
                    |MalDet uses statistical information about file anomalies to assign a probability to a file for being malicious.
                    |A probability of 50% means there is no knowledge about the file.
                    |Files with 90% probability may still be non-malicious and vice versa for files with 10% probability.
                    |MalDet is still experimental and not a substitute for any antivirus software!
                    |MalDet is made with PortEx: https://github.com/katjahahn/PortEx
                    |""".stripMargin

  private val usage = """Usage: java -jar maldet.jar -f <pefile>
                        |       java -jar maldet.jar -d <directory>
    """.stripMargin

  private type OptionMap = scala.collection.mutable.Map[Symbol, String]

  def main(args: Array[String]): Unit = {
    invokeCLI(args)
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
          System.err.println("file doesn't exist!");
        } else {
          println("scanning file ...")
          val prob = DetectionHeuristic(file).malwareProbability
          println("malware probability: " + (prob * 100) + "%")
          println("-done-")
        }
      } catch {
        case e: Exception => System.err.println(e.getMessage());
      }
    } else if (options.contains('directory)) {
      try {
        val foldername = options('directory)
        val folder = new File(foldername)
        println("input folder: " + foldername)
        if (!folder.exists()) {
          System.err.println("folder doesn't exist!");
        } else {
          println("scanning files ...")
          for (file <- folder.listFiles()) {
            if (isPEFile(file)) {
              val prob = DetectionHeuristic(file).malwareProbability
              println(file.getName() + " malware probability: " + (prob * 100) + "%")
            } else {
              println(file.getName() + " is no PE file")
            }
          }
          println("-done-")
        }
      } catch {
        case e: Exception => System.err.println(e.getMessage());
      }

    } else {
      println(usage)
    }
  }

  private def isPEFile(file: File): Boolean = {
    !file.isDirectory() && new PESignature(file).hasSignature()
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
    val folder = new File("/home/deque/virusshare128/pe")
    val threshholdA = 0.99999
    val threshholdB = 0.99
    val threshholdC = 0.95
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
          println("malicious by threshhold 0.99: " + malcounterB + " ratio " + (malcounterB.toDouble / total.toDouble))
          println("malicious by threshhold 0.95: " + malcounterC + " ratio " + (malcounterC.toDouble / total.toDouble))
          println("malicious by threshhold 0.999: " + malcounterA + " ratio " + (malcounterA.toDouble / total.toDouble))
        }
      } catch {
        case e: Exception => System.err.println(e.getMessage);
      }
    }
    println("files read: " + total)
    println("malicious by threshhold 0.95: " + malcounterB + " ratio " + (malcounterB.toDouble / total.toDouble))
    println("malicious by threshhold 0.90: " + malcounterC + " ratio " + (malcounterC.toDouble / total.toDouble))
    println("malicious by threshhold 0.999: " + malcounterA + " ratio " + (malcounterA.toDouble / total.toDouble))
  }

  def newInstance(file: File): DetectionHeuristic = apply(file)

  def apply(file: File): DetectionHeuristic = {
    val data = PELoader.loadPE(file)
    val scanner = PEAnomalyScanner.newInstance(data)
    val list = scanner.getAnomalies.asScala.toList
    new DetectionHeuristic(list, probabilities)
  }

  private def clean(bad: Map[String, Array[String]],
    good: Map[String, Array[String]]): (Map[String, Double], Map[String, Double]) = {
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
    //    println("probs nr: " + malprobs.size)
    //    println("cleaned: " + (rawMalprobs.size - malprobs.size))
    //    println("cleaning threshhold: " + threshhold)
    //    println()
    (malprobs map tupled { (key: String, malicious: Double) =>
      val subtype = AnomalySubType.valueOf(key)
      val good = goodprobs.getOrElse(key, 0.5)
      val prob = AnomalyProb(malicious, good)
      (subtype, prob)
    }).toMap ++
      (goodprobs.filterNot(t => malprobs.contains(t._1)) map tupled { (key, good) =>
        val subtype = AnomalySubType.valueOf(key)
        val malicious = malprobs.getOrElse(key, 0.5)
        val prob = AnomalyProb(malicious, good)
        (subtype, prob)
      }).toMap
  }

}