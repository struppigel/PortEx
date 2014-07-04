package com.github.katjahahn

import org.testng.internal.TestResult
import java.io.File
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.PELoader
import com.github.katjahahn.parser.Mapping

object PerformanceTester {

  def main(args: Array[String]): Unit = {
    for (chunkSize <- List(512, 1024, 2048, 4096, 8192, 16384)) {
      Mapping.defaultChunkSize = chunkSize
      val durationWithChunks = testMappingPerformance(200, true)
      val durationWithoutChunks = testMappingPerformance(200, false)
      println("chunksize: " + chunkSize)
      println("time taken with chunks: " + durationWithChunks + " seconds")
      println("time taken without chunks: " + durationWithoutChunks + " seconds")
      println()
    }
  }

  def testMappingPerformance(nrOfTests: Int, useChunks: Boolean): Double = {
    Mapping.useChunks = useChunks
    val file = new File(TestreportsReader.RESOURCE_DIR +
      TestreportsReader.TEST_FILE_DIR + "/WinRar.exe");
    val data = PELoader.loadPE(file)
    var loader = new SectionLoader(data)
    loader.loadImportSection() //first load
    val startTime = System.nanoTime()
    for (i <- 0 until nrOfTests) {
      loader.loadImportSection()
    }
    val duration = System.nanoTime() - startTime
    duration / 1000000000.toDouble
  }
}