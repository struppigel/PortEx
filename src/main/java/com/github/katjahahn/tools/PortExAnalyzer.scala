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

import com.github.katjahahn.tools.visualizer.VisualizerBuilder
import com.github.katjahahn.tools.sigscanner.FileTypeScanner
import com.github.katjahahn.parser.sections.rsrc.icon.IconParser
import com.github.katjahahn.parser.PELoader
import com.github.katjahahn.parser.ScalaIOUtil.using
import scala.PartialFunction._
import scala.collection.JavaConverters._
import javax.imageio.ImageIO
import com.github.katjahahn.parser.IOUtil.NL
import com.github.katjahahn.parser.PESignature
import java.io.IOException
import com.github.katjahahn.tools.visualizer.ImageUtil
import com.github.katjahahn.tools.sigscanner.Signature
import java.io.File
import java.nio.file.Paths
import java.io.FileWriter
import com.github.katjahahn.tools.visualizer.ColorableItem
import java.awt.Color

/**
 * Command line frontend of PortEx
 */
object PortExAnalyzer {

  private val version = """version: 0.4.2
    |author: Katja Hahn
    |last update: 23. Okt 2015""".stripMargin

  private val title = """PortEx Analyzer""" + NL

  private val usage = """usage: 
    | java -jar PortexAnalyzer.jar -v
    | java -jar PortexAnalyzer.jar -h
    | java -jar PortexAnalyzer.jar [-a] [-o <outfile>] [-p <imagefile>] [-i <folder>] <PEfile>
    |
    | -h,--help          show help
    | -v,--version       show version
    | -a,--all           show all info (might be slow and unstable)
    | -o,--output        write report to output file
    | -p,--picture       write image representation of the PE to output file
    | -i,--ico           extract icons from the resource section as .ico file
    """.stripMargin

  private type OptionMap = scala.collection.mutable.Map[Symbol, String]

  def main(args: Array[String]): Unit = {
    invokeCLI(args)
  }
  private def invokeCLI(args: Array[String]): Unit = {
    println(title)
    val options = nextOption(scala.collection.mutable.Map(), args.toList)
    if (args.length == 0) {
      println(usage)
    } else {
      if (options.contains('version)) {
        println(version)
        println()
      }
      if (options.contains('help)) {
        println(usage)
        println()
      }
      if (options.contains('inputfile)) {
        try {
          val file = new File(options('inputfile))
          if (file.exists) {
            if (isPEFile(file)) {
              val reporter = ReportCreator.newInstance(file)
              val all = (options.contains('all))
              reporter.setShowAll(all)
              if (options.contains('output)) {
                writeReport(reporter, new File(options('output)))
              } else {
                reporter.printReport()
                println("--- end of report ---")
                println()
              }

              if (options.contains('icons)) {
                val folder = new File(options('icons))
                if (folder.isDirectory && folder.exists) {
                  extractIcons(file, folder)
                } else {
                  println("No valid directory: " + folder.getAbsolutePath)
                }
              }
            } else {
              if (options.contains('output)) {
                writeFileTypeReport(file, new File(options('output)))
              } else {
                println("The given file is no PE file! ")
                printFileTypeReport(file)
              }
            }
            if (options.contains('picture)) {
              val imageFile = new File(options('picture))
              writePicture(file, imageFile)
              println("picture successfully created and saved to " + imageFile.getAbsolutePath)
              println()
            }
          } else {
            System.err.println("file doesn't exist")
          }
        } catch {
          case e: Exception => System.err.println("Error: " + e.getMessage); e.printStackTrace();
        }
      }
    }
  }

  private def extractIcons(peFile: File, folder: File): Unit = {
    val grpIcoResources = IconParser.extractGroupIcons(peFile).asScala
    var nr = 0
    for (grpIconResource <- grpIcoResources) {
      val icoFile = grpIconResource.toIcoFile()
      while (Paths.get(folder.getAbsolutePath, nr + ".ico").toFile.exists()) {
        nr += 1
      }
      val dest = Paths.get(folder.getAbsolutePath, nr + ".ico").toFile
      icoFile.saveTo(dest)
      println("file " + dest.getName() + " written")
    }
  }

  private def writePicture(file: File, imageFile: File): Unit = {
    val pixelSize = 4
    val fileWidth = 256
    val MAX_HEIGHT = 1000
    def height(bytes: Int): Int = {
      val nrOfPixels = file.length / bytes.toDouble
      val pixelsPerRow = fileWidth / pixelSize.toDouble
      val pixelsPerCol = nrOfPixels / pixelsPerRow
      Math.ceil(pixelsPerCol * pixelSize).toInt
    }
    val bytesPerPixel = {
      var res = 1
      while(height(res) > MAX_HEIGHT) res *= 2
      res
    }
    val bytePlotPixelSize = if(fileWidth * height(bytesPerPixel) > file.length()) pixelSize else 1
    val viBuilder = new VisualizerBuilder().setFileWidth(fileWidth).setPixelSize(pixelSize).setBytesPerPixel(bytesPerPixel, file.length).setColor(ColorableItem.ENTROPY,Color.cyan)
    val vi = viBuilder.build()
    val vi2 = new VisualizerBuilder().setPixelSize(bytePlotPixelSize).setFileWidth(fileWidth).setHeight(height(bytesPerPixel)).build()
    val entropyImage = vi.createEntropyImage(file)
    //more fine grained bytePlot image, thus another visualizer
    val bytePlot = vi2.createBytePlot(file)
    val appendedImage = ImageUtil.appendImages(bytePlot, entropyImage)
    if (isPEFile(file)) {
      val structureImage = vi.createImage(file)
      val appendedImage1 = ImageUtil.appendImages(appendedImage, structureImage)
      val legendImage = vi.createLegendImage(true, true, true)
      val appendedImage2 = ImageUtil.appendImages(appendedImage1, legendImage)
      ImageIO.write(appendedImage2, "png", imageFile)
    } else {
      val legendImage = vi.createLegendImage(true, true, false)
      val appendedImage2 = ImageUtil.appendImages(appendedImage, legendImage)
      ImageIO.write(appendedImage2, "png", imageFile)
    }
  }

  private def printFileTypeReport(file: File): Unit = {
    def bytesMatched(sig: Signature): Int =
      sig.signature.count(cond(_) { case Some(s) => true })
    var results = FileTypeScanner(file).scanAt(0)
    if (results.isEmpty) println("No matching file-type signatures found")
    else if (results.size == 1)
      println("The file could be of the following type: ")
    else
      println("The file could be of one of the following types: ")
    println()
    results.foreach(result =>
      println(s"* ${result._1.name}, ${bytesMatched(result._1)} bytes matched"))
  }

  private def writeFileTypeReport(file: File, outFile: File): Unit = {
    if (outFile.getName().isEmpty()) {
      throw new IOException("File name for output file is empty")
    }
    if (outFile.exists()) {
      throw new IOException("Output file " + file.getAbsoluteFile() + " already exists")
    }

    def bytesMatched(sig: Signature): Int =
      sig.signature.count(cond(_) { case Some(s) => true })

    using(new FileWriter(outFile, true)) { fw =>
      fw.write("The given file is no PE file!")
      var results = FileTypeScanner(file).scanAt(0)
      if (results.isEmpty) fw.write("No matching file-type signatures found" + NL)
      else if (results.size == 1)
        fw.write("The file could be of the following type: " + NL)
      else
        fw.write("The file could be of one of the following types: " + NL)
      fw.write(NL)
      results.foreach(result =>
        fw.write(s"* ${result._1.name}, ${bytesMatched(result._1)} bytes matched" + NL))
    }
  }

  private def isPEFile(file: File): Boolean =
    new PESignature(file).exists()

  private def writeReport(reporter: ReportCreator, file: File): Unit = {
    if (file.getName().isEmpty()) {
      throw new IOException("File name for output file is empty")
    }
    if (file.exists()) {
      throw new IOException("Output file " + file.getAbsoluteFile() + " already exists")
    }
    using(new FileWriter(file, true)) { fw =>
      println("Creating report file...")
      fw.write(reporter.reportTitle)
      println("Writing header reports...")
      fw.write(reporter.headerReports)
      println("Writing section reports...")
      fw.write(reporter.specialSectionReports)
      println("Writing analysis reports...")
      fw.write(reporter.additionalReports)
      fw.write("--- end of report ---")
      println("Done!")
    }
  }

  private def nextOption(map: OptionMap, list: List[String]): OptionMap = {
    list match {
      case Nil => map
      case "-h" :: tail =>
        nextOption(map += ('help -> ""), tail)
      case "--help" :: tail =>
        nextOption(map += ('help -> ""), tail)
      case "-v" :: tail =>
        nextOption(map += ('version -> ""), tail)
      case "--version" :: tail =>
        nextOption(map += ('version -> ""), tail)
      case "-a" :: tail => 
        nextOption(map += ('all -> ""), tail)
      case "--all" :: tail => 
        nextOption(map += ('all -> ""), tail)
      case "-o" :: value :: tail =>
        nextOption(map += ('output -> value), tail)
      case "--output" :: value :: tail =>
        nextOption(map += ('output -> value), tail)
      case "-p" :: value :: tail =>
        nextOption(map += ('picture -> value), tail)
      case "--picture" :: value :: tail =>
        nextOption(map += ('picture -> value), tail)
      case "-i" :: value :: tail =>
        nextOption(map += ('icons -> value), tail)
      case "--ico" :: value :: tail =>
        nextOption(map += ('icons -> value), tail)
      case value :: Nil => nextOption(map += ('inputfile -> value), list.tail)
      case option :: tail =>
        println("Unknown option " + option + "\n" + usage)
        sys.exit(1)
    }
  }

}