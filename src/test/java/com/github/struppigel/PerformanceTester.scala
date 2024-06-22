package com.github.struppigel

import com.github.struppigel.parser.{Mapping, PELoader}
import com.github.struppigel.parser.sections.SectionLoader

import java.io.File

object PerformanceTester {

  def main(args: Array[String]): Unit = {
    testMappingPerformance()
  }
  
  def testMappingPerformance(): Unit = {
    for (chunkSize <- List(512, 1024, 2048, 4096, 8192, 16384)) {
      Mapping.defaultChunkSize = chunkSize
      val durationWithChunks = testMappingPerformance(20, true)
      val durationWithoutChunks = testMappingPerformance(20, false)
      println("chunksize: " + chunkSize)
      println("time taken with chunks:    " + durationWithChunks + " seconds")
      println("time taken without chunks: " + durationWithoutChunks + " seconds")
      println()
    }
  }

  def testMappingPerformance(nrOfTests: Int, useChunks: Boolean): Double = {
    Mapping.useChunks = useChunks
    val folder = new File(TestreportsReader.RESOURCE_DIR +
      TestreportsReader.TEST_FILE_DIR)
    var duration = 0.toDouble
    val files = folder.listFiles
    for (file <- files) {
      val data = PELoader.loadPE(file)
      val loader = new SectionLoader(data)
      // first loads
      loader.maybeLoadImportSection() 
      loader.maybeLoadExportSection()
      
      val startTime = System.nanoTime()
      for (i <- 0 until nrOfTests) {
        loader.maybeLoadImportSection()
        loader.maybeLoadExportSection()
      }
      val partduration = (System.nanoTime() - startTime) / nrOfTests.toDouble
      duration += partduration
    }
    duration  / 1000000000.toDouble
  }
}