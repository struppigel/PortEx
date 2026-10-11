/**
 * *****************************************************************************
 * Copyright 2014 Karsten Hahn
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
package io.github.struppigel.tools

import io.github.struppigel.parser.IOUtil.NL
import io.github.struppigel.parser.ScalaIOUtil.using
import io.github.struppigel.parser.{PELoader, PESignature}
import io.github.struppigel.parser.optheader.StandardFieldEntryKey
import io.github.struppigel.parser.sections.SectionLoader
import io.github.struppigel.tools.layout.{FileRegion, RegionType, StructureMap}
import io.github.struppigel.tools.visualizer.engine.{ByteStatistics, CachedByteSource, FileVisualization, ProgressListener, ViewMapping}
import io.github.struppigel.tools.visualizer.render.{RegionColorScheme, RenderStyle, Track, VisualizationRenderer}
import io.github.struppigel.tools.visualizer.{ColorableItem, ImageUtil, VisualizerBuilder}
import io.github.struppigel.parser.{MemoryMappedPE, PhysicalLocation}
import io.github.struppigel.tools.sigscanner.FileTypeScanner

import java.awt.Color
import java.io.{File, FileWriter, IOException}
import java.lang.Long.parseLong
import java.nio.file.{Files, Paths}
import javax.imageio.ImageIO
import scala.annotation.tailrec
import scala.collection.JavaConverters._
import scala.io.Source._

/**
 * Command line frontend of PortEx
 */
object PortExAnalyzer {

  private val version = """version: 0.13.0
    |author: Karsten Hahn
    |last update: 11. October 2026""".stripMargin

  private val title = """PortEx Analyzer""" + NL

  private val usage = """usage: 
    | java -jar PortexAnalyzer.jar -v
    | java -jar PortexAnalyzer.jar -h
    | java -jar PortexAnalyzer.jar -l <offset1,offset2,offset3,...> <PEfile>
    | java -jar PortexAnalyzer.jar --layout <PEfile>
    | java -jar PortexAnalyzer.jar --rawep <PEfile>
    | java -jar PortexAnalyzer.jar --dump <all|resources|overlay|sections|ico|certificates> <imagefile>
    | java -jar PortexAnalyzer.jar --pdiff <file1> <file2> <imagefile>
    | java -jar PortexAnalyzer.jar [-a] [-o <outfile>] [-p <imagefile> [-bps <bytes>] [--visoverlay <textfile>]] [-i <folder>] <PEfile>
    | java -jar PortexAnalyzer.jar -p <imagefile> --from <offset> --to <offset> [-bps <bytes>] <file>
    |
    | -h,--help          show help
    | -v,--version       show version
    | -a,--all           show all info (slow and unstable!)
    | -o,--output        write report to output file
    | -p,--picture       write image representation of the PE to output file
    | -bps               bytes per square in the image
    | --from, --to       picture of an offset range, hex bytes for up to 4 KB
    | -l,--loc           show location for specified offset
    | --layout           show all structures with their file ranges
    | --rawep            print file offset of entry point (decimal)
    | --dump             dump resources, overlay, sections, icons, certificates
    | --pdiff            create a diff visualization
    | -i,--ico           extract icons from the resource section as .ico file
    """.stripMargin

  private type OptionMap = scala.collection.mutable.Map[Symbol, String]

  def main(args: Array[String]): Unit = {
    val exitCode = invokeCLI(args)
    if (exitCode != 0) sys.exit(exitCode)
  }
  private def invokeCLI(args: Array[String]): Int = {
    var exitCode = 0
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
      if (options.contains('diff)) {
        val file = new File(options('diff))
        if (file.exists) {
          writeDiffReport(file)
        } else {
          System.err.println("file doesn't exist")
          exitCode = 1
        }
      }
      if (options.contains('repair)) {
        val inFile = new File(options('repair))
        val outFile = new File(options('repair) + ".repaired")
        if (inFile.exists) {
          PEAutoRepair.apply(inFile, outFile).repair()
        } else {
          System.err.println("file doesn't exist")
          exitCode = 1
        }
      }
      if (options.contains('inputfile)) {
        try {
          val file = new File(options('inputfile))
          if (file.exists && file.isFile) {
            if (isPEFile(file)) {
              if (options.contains('location)){
                val offsetStr = options('location)
                if (!printLocationsFor(offsetStr, file)) exitCode = 1
              }
              else if (options.contains('layout)) {
                print(StructureMap.of(PELoader.loadPE(file)).getReport)
              }
              else if (options.contains('rawep)) {
                val pedata = PELoader.loadPE(file)
                val ep = pedata.getOptionalHeader.getStandardFieldEntry(StandardFieldEntryKey.ADDR_OF_ENTRY_POINT).getValue
                val mappedPE = MemoryMappedPE(pedata, new SectionLoader(pedata))
                val rawep = mappedPE.virtToPhysAddress(ep)
                println("entry point file offset: " + rawep)
              }
              else if (options.contains('dump)) {
                val dumpOption = options('dump)
                dumpStuff(file, dumpOption)
              } else {
                val reporter = ReportCreator.newInstance(file)
                val all = options.contains('all)
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
                    val dumper = new PEFileDumper(PELoader.loadPE(file), folder)
                    dumper.dumpIcons()
                  } else {
                    println("No valid directory: " + folder.getAbsolutePath)
                  }
                }
              }
            } else {
              exitCode = 1
              if (options.contains('output)) {
                writeFileTypeReport(file, new File(options('output)))
              } else {
                println("The given file is no PE file!" + NL + file.getAbsolutePath + NL +
                  "Try '--repair' option if you think it is a broken PE." + NL)
                printFileTypeReport(file)
              }
            }
            if (options.contains('picture) && (options.contains('from) || options.contains('to))) {
              println("creating visualization...")
              val imageFile = new File(options('picture))
              val from = options.get('from).map(parseOffset).getOrElse(Some(0L))
              val to = options.get('to).map(parseOffset).getOrElse(Some(file.length))
              if (from.isEmpty || to.isEmpty || to.get <= from.get || from.get >= file.length) {
                System.err.println("Invalid offset range, --from must be before --to and within the file")
                exitCode = 1
              } else {
                writeZoomedPicture(file, imageFile, from.get, to.get, options.get('bps).map(_.toLong))
                println("picture successfully created and saved to " + imageFile.getAbsolutePath)
                println()
              }
            } else if (options.contains('picture)) {
              println("creating visualization...")
              val imageFile = new File(options('picture))
              if (options.contains('bps)) {
                val bps = options('bps).toInt
                if (options.contains('visoverlay)) {
                  val visFile = new File(options('visoverlay))
                  writePicture(file, imageFile, Some(bps), Some(visFile))
                } else {
                  writePicture(file, imageFile, Some(bps))
                }
              } else {
                if (options.contains('visoverlay)) {
                  val visFile = new File(options('visoverlay))
                  writePicture(file, imageFile, None, Some(visFile))
                } else {
                  writePicture(file, imageFile)
                }
              }
              println("picture successfully created and saved to " + imageFile.getAbsolutePath)
              println()
            }
          } else if (file.exists) {
            System.err.println("Input is not a regular file: " + file.getAbsolutePath)
            exitCode = 1
          } else {
            if (options.contains('pdiffA) && options.contains('pdiffB)) {
              val pdiffAFile = new File(options('pdiffA))
              val pdiffBFile = new File(options('pdiffB))
              val outFile = file
              if (pdiffAFile.length > pdiffBFile.length) {
                writeDiffPicture(pdiffAFile, pdiffBFile, outFile)
              } else writeDiffPicture(pdiffBFile, pdiffAFile, outFile)

              println("picture successfully created and saved to " + outFile.getAbsolutePath)
              println()
            } else {
              System.err.println("file doesn't exist")
              exitCode = 1
            }
          }
        } catch {
          case e: Exception =>
            System.err.println("Error: " + e.getMessage)
            e.printStackTrace()
            exitCode = 1
        }
      }
    }
    exitCode
  }
  
  /**
   * Prints the structures at each offset, innermost first, e.g.
   * {{{
   * 0x80: PE Signature [0x80,0x84) < Headers [0x0,0x400)
   * 0x80: hints: Entry Point (+/-0x6000)
   * }}}
   * The hints keep the labels of former versions for scripts.
   *
   * @return true if all offsets were valid
   */
  private def printLocationsFor(offsetsStr: String, file: File): Boolean = {
    val data = PELoader.loadPE(file)
    val map = StructureMap.of(data)
    var valid = true
    for (offsetStr <- offsetsStr.split(",").map(_.trim)) {
      parseOffset(offsetStr) match {
        case None =>
          System.err.println("Invalid offset: " + offsetStr)
          valid = false
        case Some(offset) =>
          val prefix = "0x" + java.lang.Long.toHexString(offset) + ": "
          val regions = map.regionsAt(offset).asScala
          if (offset >= map.getFileLength) println(prefix + "beyond the end of the file (0x" +
            java.lang.Long.toHexString(map.getFileLength) + ")")
          else if (regions.isEmpty) println(prefix + "no structure")
          else println(prefix + regions.mkString(" < "))
          val hints = locationHints(map, data.getSectionTable.getNumberOfSections, offset)
          if (hints.nonEmpty) println(prefix + "hints: " + hints.mkString(", "))
      }
    }
    valid
  }

  private def parseOffset(str: String): Option[Long] =
    try {
      val offset = if (str.toLowerCase.startsWith("0x")) parseLong(str.substring(2), 16) else str.toLong
      if (offset < 0) None else Some(offset)
    } catch {
      case _: NumberFormatException => None
    }

  /** the coarse labels of former versions that hold for the offset */
  private def locationHints(map: StructureMap, numberOfSections: Int, offset: Long): List[String] = {
    def within(start: Long, end: Long): Boolean = offset >= start && offset < end
    val lastSection = map.getRegions(RegionType.SECTION).asScala.filter { r =>
      r.getAttributes.get(FileRegion.ATTR_SECTION_NUMBER) == numberOfSections.toString && within(r.getStart, r.getEnd)
    }.map(_ => "LastSection")
    val entryPoint = map.getRegions(RegionType.ENTRY_POINT).asScala.filter { r =>
      within(r.getStart - 0x6000, r.getStart + 0x6000)
    }.map(_ => "Entry Point (+/-0x6000)")
    val overlayStart = map.getRegions(RegionType.OVERLAY).asScala.filter { r =>
      within(r.getStart, r.getStart + 0x10000)
    }.map(_ => "OverlayStart")
    (lastSection ++ entryPoint ++ overlayStart).toList
  }

  private def dumpStuff(file: File, dumpOption: String): Unit = {
    try {
      val peData = PELoader.loadPE(file)
      val outFolder = if (file.getParentFile != null) {
        Paths.get(file.getParentFile.getAbsolutePath, "portex.dumps")
      } else Paths.get("portex.dumps")
      if (!outFolder.toFile.exists) {
        Files.createDirectory(outFolder)
      }
      if (outFolder.toFile.isDirectory) {
        val dumper = new PEFileDumper(peData, outFolder.toFile)
        dumpOption match {
          case "all" =>
            dumper.dumpPEFiles()
            dumper.dumpResources()
            dumper.dumpOverlay()
            dumper.dumpSections()
            dumper.dumpIcons()
            dumper.dumpCertificates()
          case "certificates" => dumper.dumpCertificates()
          case "pe"        => dumper.dumpPEFiles()
          case "resources" => dumper.dumpResources()
          case "overlay"   => dumper.dumpOverlay()
          case "sections"  => dumper.dumpSections()
          case "ico"       => dumper.dumpIcons()
          case _           => System.err.println("dump option " + dumpOption + " does not exist.")
        }
      } else {
        System.err.println("There is already a file named " + outFolder.toFile.getAbsolutePath + " that is not a folder!")
      }
    } catch {
      case e: Exception => System.err.println(e.getMessage); e.printStackTrace();
    }
  }

  private def writeDiffReport(file: File): Unit = {
    val files: List[File] = (if (file.isDirectory) file.listFiles().toList
    else using(fromFile(file)){_.getLines}.map(new File(_))).toList
    DiffReportCreator.apply(files).printReport()
  }

  private def writeDiffPicture(fileBig: File, fileSmall: File, imageFile: File): Unit = {
    val pixelSize = 4
    val fileWidth = 256
    val MAX_HEIGHT = 1000
    def height(bytes: Int): Int = {
      val nrOfPixels = fileBig.length / bytes.toDouble
      val pixelsPerRow = fileWidth / pixelSize.toDouble
      val pixelsPerCol = nrOfPixels / pixelsPerRow
      Math.ceil(pixelsPerCol * pixelSize).toInt
    }
    val bytesPerPixel = {
      var res = 1
      while (height(res) > MAX_HEIGHT) res *= 2
      res
    }
    val bytePlotPixelSize = if (fileWidth * height(bytesPerPixel) > fileBig.length()) pixelSize else 1
    val viBuilder = new VisualizerBuilder().setFileWidth(fileWidth).setPixelSize(pixelSize).setBytesPerPixel(bytesPerPixel, fileBig.length).setColor(ColorableItem.ENTROPY, Color.cyan)
    val vi = viBuilder.build()
    val vi2 = new VisualizerBuilder().setPixelSize(bytePlotPixelSize).setFileWidth(fileWidth).setHeight(height(bytesPerPixel)).build()
    val entropyImageBig = vi.createEntropyImage(fileBig)
    val entropyImageSmall = vi.createEntropyImage(fileSmall)
    val entropyImage = vi.createDiffImage(entropyImageBig, entropyImageSmall)
    //more fine grained bytePlot image, thus another visualizer
    val bytePlotSmall = vi2.createBytePlot(fileSmall)
    val bytePlotBig = vi2.createBytePlot(fileBig)
    val bytePlot = vi2.createDiffImage(bytePlotBig, bytePlotSmall)
    val appendedImage = ImageUtil.appendImages(bytePlot, entropyImage)
    if (isPEFile(fileBig) && isPEFile(fileSmall)) {
      val structureImageBig = vi.createImage(PELoader.loadPE(fileBig))
      val structureImageSmall = vi.createImage(PELoader.loadPE(fileSmall))
      val structureImage = vi.createDiffImage(structureImageBig, structureImageSmall)
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

  private def readVisOverlay(file: File): java.util.List[PhysicalLocation] = {
    val list = new java.util.ArrayList[PhysicalLocation]()
    if (file.exists()) {  
      var offset: Option[Int] = None
      var size: Option[Int] = None
      for (line <- using(scala.io.Source.fromFile(file)){_.getLines}) {
        if (line.contains("offset")) {
          offset = readVisFileValue(line)
        } else if (line.contains("size")) {
          size = readVisFileValue(line)
        }

        if(offset.isDefined && size.isDefined) {
          list.add(new PhysicalLocation(offset.get, size.get))
          offset = None
          size = None
        }
        
        if (line.contains("}")) {
          offset = None
          size = None
        }
      }

    }
    list
  }

  private def readVisFileValue(line: String): Option[Int] = {
    val splitLine = line.split(":")
    if (splitLine.length > 1) {
      var offsetString = splitLine(1).replace("\"", "").replace(",", "").trim()
      if (offsetString.contains("x")) {
        offsetString = offsetString.split("x")(1)
      }
      val value = Integer.parseInt(offsetString, 16)
      Some(value)
    } else None
  }

  /**
   * Writes byte plot, entropy and structure of an offset range with an offset
   * ruler and a legend. Ranges of up to 4 KB get hex and ASCII tracks with
   * one byte per cell, larger ones are fitted to about 1000 pixels height
   * unless bytes per square are given.
   */
  private def writeZoomedPicture(file: File, imageFile: File, from: Long, to: Long, bps: Option[Long]): Unit = {
    val length = file.length
    val end = math.min(to, length)
    val range = end - from
    val hex = range <= 0x1000 && bps.forall(_ == 1)
    val columns = if (hex) 16 else 64
    val (cellWidth, cellHeight) = if (hex) (8, 14) else (4, 4)
    val bytesPerCell = bps.getOrElse(
      if (hex) 1L else ViewMapping.fitBytesPerCell(range, columns, 1000 / cellHeight, true))
    val mapping = new ViewMapping(length, from, math.max(1L, bytesPerCell), columns)
    val rows = ((range + mapping.getBytesPerRow - 1) / mapping.getBytesPerRow).toInt
    val map = if (isPEFile(file)) StructureMap.of(PELoader.loadPE(file)) else StructureMap.empty(length)
    val stats = new ByteStatistics(file)
    // only cells of at least one block use the statistics of the whole file
    if (mapping.getBytesPerCell >= stats.getBlockSize) stats.compute(ProgressListener.NONE)
    val tracks = if (hex) List(Track.BYTEPLOT, Track.ENTROPY, Track.STRUCTURE, Track.HEX, Track.ASCII)
    else List(Track.BYTEPLOT, Track.ENTROPY, Track.STRUCTURE)
    using(new CachedByteSource(file)) { source =>
      val vis = new FileVisualization(map, stats, source, RegionColorScheme.of(map))
      val image = VisualizationRenderer.renderComposite(vis, mapping, 0, math.max(1, rows), tracks.asJava,
        cellWidth, cellHeight, RenderStyle.defaults(), true)
      ImageIO.write(image, "png", imageFile)
    }
  }

  private def writePicture(file: File, imageFile: File, bps: Option[Int] = None,
                           visFile: Option[File] = None): Unit = {
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
      if (bps.isDefined) bps.get else {
        var res = 1
        while (height(res) > MAX_HEIGHT) res *= 2
        res
      }
    }
    val bytePlotPixelSize = if (fileWidth * height(bytesPerPixel) > file.length()) pixelSize else 1
    val viBuilder = new VisualizerBuilder().setFileWidth(fileWidth).setPixelSize(pixelSize).setBytesPerPixel(bytesPerPixel, file.length).setColor(ColorableItem.ENTROPY, Color.cyan)
    if (visFile.isDefined) viBuilder.setVisOverlay(readVisOverlay(visFile.get))
    val vi = viBuilder.build()
    val vi2Builder = new VisualizerBuilder().setPixelSize(bytePlotPixelSize).setFileWidth(fileWidth).setHeight(height(bytesPerPixel))
    if (visFile.isDefined) vi2Builder.setVisOverlay(readVisOverlay(visFile.get))
    val vi2 = vi2Builder.build()
    if (isPEFile(file)) {
      // parse once for all images
      val pe = PELoader.loadPE(file)
      val entropyImage = vi.createEntropyImage(pe)
      //more fine grained bytePlot image, thus another visualizer
      val bytePlot = vi2.createBytePlot(pe)
      val appendedImage = ImageUtil.appendImages(bytePlot, entropyImage)
      val structureImage = vi.createImage(pe)
      val appendedImage1 = ImageUtil.appendImages(appendedImage, structureImage)
      val legendImage = vi.createLegendImage(true, true, true)
      val appendedImage2 = ImageUtil.appendImages(appendedImage1, legendImage)
      ImageIO.write(appendedImage2, "png", imageFile)
    } else {
      val entropyImage = vi.createEntropyImage(file)
      val bytePlot = vi2.createBytePlot(file)
      val appendedImage = ImageUtil.appendImages(bytePlot, entropyImage)
      val legendImage = vi.createLegendImage(true, true, false)
      val appendedImage2 = ImageUtil.appendImages(appendedImage, legendImage)
      ImageIO.write(appendedImage2, "png", imageFile)
    }
  }

  private def printFileTypeReport(file: File): Unit = {
    val results = FileTypeScanner._scan(file)
    if (results.isEmpty) println("No matching file-type signatures found")
    else if (results.size == 1)
      println("The file could be of the following type: ")
    else
      println("The file could be of one of the following types: ")
    println()
    results.foreach(result =>
      println(s"* ${result.getName}, ${result.getLength} bytes matched"))
  }

  private def writeFileTypeReport(file: File, outFile: File): Unit = {
    if (outFile.getName.isEmpty) {
      throw new IOException("File name for output file is empty")
    }
    if (outFile.exists()) {
      throw new IOException("Output file " + outFile.getAbsoluteFile + " already exists")
    }

    using(new FileWriter(outFile, true)) { fw =>
      fw.write("The given file is no PE file!" + NL +
        "Try '--repair' option if you think it is a broken PE." + NL)
      val results = FileTypeScanner._scan(file)
      if (results.isEmpty) fw.write("No matching file-type signatures found" + NL)
      else if (results.size == 1)
        fw.write("The file could be of the following type: " + NL)
      else
        fw.write("The file could be of one of the following types: " + NL)
      fw.write(NL)
      results.foreach(result =>
        fw.write(s"* ${result.getName}, ${result.getLength} bytes matched" + NL))
    }
  }

  private def isPEFile(file: File): Boolean =
    new PESignature(file).exists()

  private def writeReport(reporter: ReportCreator, file: File): Unit = {
    if (file.getName.isEmpty) {
      throw new IOException("File name for output file is empty")
    }
    if (file.exists()) {
      throw new IOException("Output file " + file.getAbsoluteFile + " already exists")
    }
    using(new FileWriter(file, true)) { fw =>
      println("Creating report file...")
      fw.write(reporter.reportTitle)
      println("Writing reversing hints...")
      fw.write(reporter.reversingHintsReport())
      println("Writing header reports...")
      fw.write(reporter.headerReports())
      println("Writing section reports...")
      fw.write(reporter.specialSectionReports())
      println("Writing analysis reports...")
      fw.write(reporter.additionalReports())
      fw.write("--- end of report ---")
      println("Report done!")
    }
  }

  @tailrec
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
      case "--repair" :: value :: tail =>
        nextOption(map += ('repair -> value), tail)
      case "--dump" :: value :: tail =>
        nextOption(map += ('dump -> value), tail)
      case "-o" :: value :: tail =>
        nextOption(map += ('output -> value), tail)
      case "-l" :: value :: tail =>
        nextOption(map += ('location -> value), tail)
      case "--location" :: value :: tail =>
        nextOption(map += ('location -> value), tail)
      case "--loc" :: value :: tail =>
        nextOption(map += ('location -> value), tail)
      case "--layout" :: tail =>
        nextOption(map += ('layout -> ""), tail)
      case "--from" :: value :: tail =>
        nextOption(map += ('from -> value), tail)
      case "--to" :: value :: tail =>
        nextOption(map += ('to -> value), tail)
      case "--rawep" :: tail =>
        nextOption(map += ('rawep -> ""), tail)
      case "--output" :: value :: tail =>
        nextOption(map += ('output -> value), tail)
      case "-p" :: value :: tail =>
        nextOption(map += ('picture -> value), tail)
      case "--picture" :: value :: tail =>
        nextOption(map += ('picture -> value), tail)
      case "-bps" :: value :: tail =>
        nextOption(map += ('bps -> value), tail)
      case "--visoverlay" :: value :: tail =>
        nextOption(map += ('visoverlay -> value), tail)
      case "-i" :: value :: tail =>
        nextOption(map += ('icons -> value), tail)
      case "--ico" :: value :: tail =>
        nextOption(map += ('icons -> value), tail)
      case "--diff" :: value :: _ =>
        nextOption(map += ('diff -> value), list.tail)
      case "--pdiff" :: value1 :: value2 :: tail =>
        nextOption(map += ('pdiffA -> value1, 'pdiffB -> value2), tail)
      case value :: Nil => nextOption(map += ('inputfile -> value), list.tail)
      case option :: _ =>
        println("Unknown option " + option + "\n" + usage)
        sys.exit(1)
    }
  }
}