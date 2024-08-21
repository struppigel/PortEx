package com.github.struppigel.tools.rehints.scanning

import com.github.struppigel.tools.rehints.ReHintScannerUtils.{constructReHintIfAnyPdbPath, optionToList}
import com.github.struppigel.tools.rehints.{ReHint, ReHintScanner, ReHintType}

import scala.collection.mutable.ListBuffer
import com.github.struppigel.parser.IOUtil.NL

trait DotNetCoreAppBundleScanning extends ReHintScanner {

  abstract override def scanReport(): String =
    "Applied DotNetCoreAppBundleScanning" + NL + super.scanReport

  abstract override def scan(): List[ReHint] = {
    val reList = ListBuffer[ReHint]()
    reList ++= _scan()
    super.scan ::: reList.toList
  }

  private def _scan(): List[ReHint] = {
    val pathes = List(".Release\\corehost\\cli\\apphost\\Release\\apphost.pdb",
                      ".Release\\Corehost.Static\\singlefilehost.pdb")
    optionToList(constructReHintIfAnyPdbPath(pathes, data, ReHintType.DOT_NET_CORE_APP_BUNDLE_HINT))
  }
}
