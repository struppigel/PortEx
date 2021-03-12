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
import com.github.katjahahn.parser.MemoryMappedPE
import com.github.katjahahn.tools.sigscanner.FileTypeScanner
import com.github.katjahahn.parser.PhysicalLocation
import com.github.katjahahn.parser.optheader.StandardFieldEntryKey
import com.github.katjahahn.parser.sections.rsrc.icon.IconParser
import com.github.katjahahn.parser.sections.SectionHeaderKey
import com.github.katjahahn.parser.PELoader
import com.github.katjahahn.parser.optheader.DataDirectoryKey._
import com.github.katjahahn.parser.ScalaIOUtil.using
import scala.PartialFunction._
import scala.collection.JavaConverters._
import scala.io.Source._
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
import java.nio.file.Path
import java.nio.file.Files
import com.github.katjahahn.parser.coffheader.COFFFileHeader
import com.github.katjahahn.parser.sections.SectionLoader

/**
 * Command line frontend of PortEx
 */
object PortExAnalyzer {

  private val version = """version: 0.9.0
    |author: Karsten Philipp Boris Hahn
    |last update: 12. March 2021""".stripMargin

  private val title = """PortEx Analyzer""" + NL

  private val usage = """usage: 
    | java -jar PortexAnalyzer.jar -v
    | java -jar PortexAnalyzer.jar -h
    | java -jar PortexAnalyzer.jar -l <offset1,offset2,offset3,...> <PEfile>
    | java -jar PortexAnalyzer.jar --repair <PEfile>
    | java -jar PortexAnalyzer.jar --rawep <PEfile>
    | java -jar PortexAnalyzer.jar --dump <all|resources|overlay|sections|ico> <imagefile>
    | java -jar PortexAnalyzer.jar --diff <filelist or folder>
    | java -jar PortexAnalyzer.jar --pdiff <file1> <file2> <imagefile>
    | java -jar PortexAnalyzer.jar [-a] [-o <outfile>] [-p <imagefile> [-bps <bytes>] [--visoverlay <textfile>]] [-i <folder>] <PEfile>
    |
    | -h,--help          show help
    | -v,--version       show version
    | -a,--all           show all info (slow and unstable!)
    | -o,--output        write report to output file
    | -p,--picture       write image representation of the PE to output file
    | -bps               bytes per square in the image
    | -l,--loc           show location for specified offset
    | --rawep            print file offset of entry point (decimal)
    | --visoverlay       text file input with square pixels to mark on the visualization
    | --repair           repair the PE file, use this if your file is not recognized as PE
    | --dump             dump resources, overlay, sections, icons 
    | --diff             compare several files and show common characteristics (alpha feature)
    | --pdiff            create a diff visualization
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
      if (options.contains('diff)) {
        val file = new File(options('diff))
        if (file.exists) {
          writeDiffReport(file)
        } else {
          System.err.println("file doesn't exist")
        }
      }
      if (options.contains('repair)) {
        val inFile = new File(options('repair))
        val outFile = new File(options('repair) + ".repaired")
        if (inFile.exists) {
          PEAutoRepair.apply(inFile, outFile).repair()
        } else {
          System.err.println("file doesn't exist")
        }
      }
      if (options.contains('inputfile)) {
        try {
          val file = new File(options('inputfile))
          if (file.exists) {
            if (isPEFile(file)) {
              if (options.contains('location)){
                val offsetStr = options('location)
                printLocationsFor(offsetStr, file)
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
                    val dumper = new PEFileDumper(PELoader.loadPE(file), folder)
                    dumper.dumpIcons()
                  } else {
                    println("No valid directory: " + folder.getAbsolutePath)
                  }
                }
              }
            } else {
              if (options.contains('output)) {
                writeFileTypeReport(file, new File(options('output)))
              } else {
                println("The given file is no PE file!" + NL + file.getAbsolutePath + NL +
                  "Try '--repair' option if you think it is a broken PE." + NL)
                printFileTypeReport(file)
              }
            }
            if (options.contains('picture)) {
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
            }
          }
        } catch {
          case e: Exception => System.err.println("Error: " + e.getMessage); e.printStackTrace();
        }
      }
    }
  }
  
  private def printIffBetween(offset: Long, offsetA: Long, offsetB: Long, message: String): Unit = {
    if(offset >= offsetA && offset <= offsetB) {
        println(offset + ": " + message)
     }
  }
  
  private def printLocationsFor(offsetsStr: String, file: File): Unit = {
    try {
      val data = PELoader.loadPE(file)
      val offsets = offsetsStr.split(",")
      for (offsetStr <- offsets) {
        val offset = offsetStr.toLong
        val table = data.getSectionTable()
        val loader = new SectionLoader(data)
        // start and end of file
        printIffBetween(offset, 0L, 0x1000, "StartOfFile0x1000")
        printIffBetween(offset, 0L, 0x5000, "StartOfFile0x5000")
        printIffBetween(offset, 0L, 0x10000, "StartOfFile0x10000")
        printIffBetween(offset, file.length() - 0x6000L, file.length(), "EndOfFile0x6000")
        printIffBetween(offset, file.length() - 0x10000L, file.length(), "EndOfFile0x10000")
        // Headers
        printIffBetween(offset, 0L, data.getMSDOSHeader().getHeaderSize(), "MSDOS Header")
        val optHeaderOffset = data.getOptionalHeader().getOffset()
        printIffBetween(offset, optHeaderOffset, optHeaderOffset + data.getOptionalHeader().getSize(), "Optional Header")
        val coffHeaderOffset = data.getCOFFFileHeader().getOffset()
        printIffBetween(offset, coffHeaderOffset, coffHeaderOffset + COFFFileHeader.HEADER_SIZE, "COFF File Header")
        printIffBetween(offset, table.getOffset(), table.getOffset() + table.getSize(), "Section Table")
        
        // Sections
        for (header <- table.getSectionHeaders().asScala) {
          val sectionOffset = header.getAlignedPointerToRaw();
          val sectionSize = loader.getReadSize(header)
          val sectionEnd = sectionOffset + sectionSize
          var sizeLimit = 0x10000L
          printIffBetween(offset, sectionOffset, sectionEnd, "Section" + header.getNumber) 
          if (sectionSize < sizeLimit) {
            sizeLimit = sectionSize
          }
          printIffBetween(offset, sectionOffset, sectionOffset + sizeLimit, "Section"+header.getNumber+"Start")
          if (sectionSize > 0x10000L) {
        	  printIffBetween(offset, sectionEnd - sizeLimit, sectionEnd, "Section"+header.getNumber+"End")
          }
          if (header.getNumber == table.getNumberOfSections()) {
            printIffBetween(offset, sectionOffset, sectionEnd, "LastSection")
            printIffBetween(offset, sectionOffset, sectionOffset + sizeLimit, "LastSectionStart")
            if (sectionSize > 0x10000L) {
              printIffBetween(offset, sectionEnd - sizeLimit, sectionEnd, "LastSectionEnd")
              printIffBetween(offset, sectionEnd - 0x6000, sectionEnd, "EndOfPE")
            }
          }
        }
        
        val specials = List(RESOURCE_TABLE, IMPORT_TABLE, DELAY_IMPORT_DESCRIPTOR, EXPORT_TABLE, BASE_RELOCATION_TABLE, DEBUG)
        
        // Special Sections
        for (specialKey <- specials) {
          val section = loader.maybeLoadSpecialSection(specialKey)
          if (section.isPresent()) {
            for (loc <- section.get().getPhysicalLocations().asScala) {
              if (loc.from != -1) {
                printIffBetween(offset, loc.from, loc.from + loc.size, specialKey.toString)
              }  
            }
          }
        }
        
        // Special resources
        val rsrc = loader.loadResourceSection()
        val resources = rsrc.getResources().asScala
        for (resource <- resources) {
          val resType = resource.getType()
          val resLoc = resource.rawBytesLocation
          printIffBetween(offset, resLoc.from, resLoc.from + resLoc.size, "ResourceType " + resType)
        }
        
        // Entry point
        val epRVA = data.getOptionalHeader().get(StandardFieldEntryKey.ADDR_OF_ENTRY_POINT);
        val epSection = loader.maybeGetSectionHeaderByRVA(epRVA);
        if (epSection.isPresent()) {
          val phystovirt = epSection.get().get(SectionHeaderKey.VIRTUAL_ADDRESS) - epSection.get().get(SectionHeaderKey.POINTER_TO_RAW_DATA)
          val ep = epRVA - phystovirt
          printIffBetween(offset, ep - 0x6000, ep + 0x6000, "Entry Point (+/-0x6000)")
        }
        
        // Overlay
        val overlay = new Overlay(data);
        if (overlay.exists()) {
          printIffBetween(offset, overlay.getOffset, file.length, "Overlay")
          printIffBetween(offset, overlay.getOffset, overlay.getOffset + 0x10000, "OverlayStart")
        }
      }
    } catch {
      case e: NumberFormatException => System.err.println("Invalid offset")
      case e: Exception => System.err.println(e.getMessage); e.printStackTrace();
    }
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
      if (outFolder.toFile.isDirectory()) {
        val dumper = new PEFileDumper(peData, outFolder.toFile)
        dumpOption match {
          case "all" =>
            dumper.dumpPEFiles()
            dumper.dumpResources()
            dumper.dumpOverlay()
            dumper.dumpSections()
            dumper.dumpIcons()
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
    val files: List[File] = (if (file.isDirectory()) file.listFiles().toList
    else fromFile(file).getLines.map(new File(_))).toList
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
      val structureImageBig = vi.createImage(fileBig)
      val structureImageSmall = vi.createImage(fileSmall)
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
      for (line <- scala.io.Source.fromFile(file).getLines) {
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
      throw new IOException("Output file " + outFile.getAbsoluteFile() + " already exists")
    }

    def bytesMatched(sig: Signature): Int =
      sig.signature.count(cond(_) { case Some(s) => true })

    using(new FileWriter(outFile, true)) { fw =>
      fw.write("The given file is no PE file!" + NL +
        "Try '--repair' option if you think it is a broken PE." + NL)
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
      println("Report done!")
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
      case "--diff" :: value :: tail =>
        nextOption(map += ('diff -> value), list.tail)
      case "--pdiff" :: value1 :: value2 :: tail =>
        nextOption(map += ('pdiffA -> value1, 'pdiffB -> value2), tail)
      case value :: Nil => nextOption(map += ('inputfile -> value), list.tail)
      case option :: tail =>
        println("Unknown option " + option + "\n" + usage)
        sys.exit(1)
    }
  }
}