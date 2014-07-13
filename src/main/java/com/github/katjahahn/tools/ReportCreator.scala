package com.github.katjahahn.tools

import com.github.katjahahn.parser.PELoader
import com.github.katjahahn.parser.PEData
import java.io.File
import com.github.katjahahn.parser.IOUtil.NL
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.SectionHeaderKey._
import com.github.katjahahn.parser.sections.SectionHeader
import com.github.katjahahn.parser.sections.SectionCharacteristic
import com.github.katjahahn.tools.anomalies.PEAnomalyScanner
import com.github.katjahahn.tools.anomalies.SectionTableScanning
import com.github.katjahahn.tools.sigscanner.SignatureScanner
import com.github.katjahahn.tools.sigscanner.Jar2ExeScanner

class ReportCreator(private val data: PEData) {

  val maxSec = 5

  def report(): String = secTableReport + overlayReport + anomalyReport +
    peidReport + jar2ExeReport + maldetReport

  def jar2ExeReport(): String = {
    val scanner = new Jar2ExeScanner(data.getFile)
    if (scanner.scan.isEmpty()) ""
    else title("Jar to EXE Wrapper Scan") + NL + scanner.createReport + NL
  }

  def maldetReport(): String =
    title("Malware Detection Heuristic") + NL + "Malware probability: " +
      ("%3.2f" format (DetectionHeuristic.newInstance(data.getFile).malwareProbability * 100)) +
      " %" + NL + NL

  def overlayReport(): String = {
    val overlay = new Overlay(data.getFile)
    if (overlay.exists) title("Overlay") + NL + "Overlay at offset " +
      hexString(overlay.getOffset()) + NL + NL
    else ""
  }

  def peidReport(): String = {
    val signatures = SignatureScanner.newInstance().scanAll(data.getFile, true)
    if (signatures.isEmpty) ""
    else title("PEID Signatures") + NL + signatures.asScala.mkString(NL) + NL + NL
  }

  def anomalyReport(): String = {
    val anomalies = PEAnomalyScanner.newInstance(data).getAnomalies.asScala
    if (anomalies.isEmpty) ""
    else title("Anomalies") + NL +
      anomalies.map(a => a.toString).mkString(NL) + NL + NL
  }

  def secTableReport(): String = {
    val table = data.getSectionTable
    val allSections = table.getSectionHeaders.asScala
    val loader = new SectionLoader(data)
    val build = new StringBuilder();
    build.append(title("Section Table"))
    for (secs <- allSections.grouped(maxSec).toList) {
      val sections = secs.toList
      val tableHeader = sectionEntryLine(sections, "", (s: SectionHeader) => s.getName)
      val tableLine = pad("", tableHeader.length, "-") + NL
      build.append(tableHeader + tableLine)
      val entropy = new ShannonEntropy(data)
      build.append(sectionEntryLine(sections, "Entropy", (s: SectionHeader) =>
        "%1.2f" format entropy.forSection(s.getNumber())))
      build.append(sectionEntryLine(sections, "Pointer To Raw Data",
        (s: SectionHeader) => hexString(s.get(POINTER_TO_RAW_DATA))))
      build.append(sectionEntryLine(sections, "-> aligned (act. start)",
        (s: SectionHeader) => if (s.get(POINTER_TO_RAW_DATA) != s.getAlignedPointerToRaw())
          hexString(s.getAlignedPointerToRaw) else ""))
      build.append(sectionEntryLine(sections, "Size Of Raw Data",
        (s: SectionHeader) => hexString(s.get(SIZE_OF_RAW_DATA))))
      build.append(sectionEntryLine(sections, "-> actual read size",
        (s: SectionHeader) => if (s.get(SIZE_OF_RAW_DATA) != loader.getReadSize(s))
          hexString(loader.getReadSize(s)) else ""))
      build.append(sectionEntryLine(sections, "Physical End",
        (s: SectionHeader) => hexString(loader.getReadSize(s) + s.getAlignedPointerToRaw())))
      build.append(sectionEntryLine(sections, "Virtual Address",
        (s: SectionHeader) => hexString(s.get(VIRTUAL_ADDRESS))))
      build.append(sectionEntryLine(sections, "-> aligned",
        (s: SectionHeader) => if (s.get(VIRTUAL_ADDRESS) != s.getAlignedVirtualAddress)
          hexString(s.getAlignedVirtualAddress) else ""))
      build.append(sectionEntryLine(sections, "Virtual Size",
        (s: SectionHeader) => hexString(s.get(VIRTUAL_SIZE))))
      build.append(sectionEntryLine(sections, "-> actual virtual size", (s: SectionHeader) =>
        if (s.get(VIRTUAL_SIZE) != s.getAlignedVirtualSize())
          hexString(s.getAlignedVirtualSize()) else ""))
      build.append(sectionEntryLine(sections, "Pointer To Relocations",
        (s: SectionHeader) => hexString(s.get(POINTER_TO_RELOCATIONS))))
      build.append(sectionEntryLine(sections, "Number Of Relocations",
        (s: SectionHeader) => hexString(s.get(NUMBER_OF_RELOCATIONS))))
      build.append(sectionEntryLine(sections, "Pointer To Line Numbers",
        (s: SectionHeader) => hexString(s.get(POINTER_TO_LINE_NUMBERS))))
      build.append(sectionEntryLine(sections, "Number Of Line Numbers",
        (s: SectionHeader) => hexString(s.get(NUMBER_OF_LINE_NUMBERS))))
      for (ch <- SectionCharacteristic.values) {
        build.append(sectionEntryLine(sections, ch.shortName(),
          (s: SectionHeader) => if (s.getCharacteristics().contains(ch)) "x" else ""))
      }
      build.append(NL)
    }
    build.toString
  }

  private def sectionEntryLine(sections: List[SectionHeader], name: String, conv: SectionHeader => String): String = {
    val colWidth = 15
    val padLength = "POINTER_TO_LINE_NUMBERS  ".length
    val padding = pad(name, padLength, " ")
    val sectionValues = sections.map(s => pad(conv(s), colWidth, " ")).mkString(" ")
    if (sectionValues.trim.isEmpty()) "" else
      padding + sectionValues + NL
  }

  private def title(str: String): String = str + NL + pad("", str.length, "*") + NL

  private def pad(string: String, length: Int, padStr: String): String = {
    val padding = (for (i <- string.length until length by padStr.length)
      yield padStr).mkString
    string + padding
  }

  private def hexString(value: Long): String =
    "0x" + java.lang.Long.toHexString(value)
}

object ReportCreator {

  def newInstance(file: File): ReportCreator =
    new ReportCreator(PELoader.loadPE(file))

  def main(args: Array[String]): Unit = {
    val file = new File("/home/deque/portextestfiles/launch4jexe.exe")
    val reporter = newInstance(file)
    println(reporter.report())
  }

}