package io.github.struppigel.tools.rehints.scanning

import io.github.struppigel.tools.rehints.ReHintScannerUtils.{constructReHintIfAnyPdbPath, optionToList}
import io.github.struppigel.tools.rehints.{ReHintType}

import scala.collection.mutable.ListBuffer
import io.github.struppigel.parser.IOUtil.NL
import io.github.struppigel.tools.rehints.{ReHint, ReHintScanner}

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
