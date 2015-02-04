import AssemblyKeys._ // put this at the top of the file

assemblySettings

jarName in assembly := "portex_1.0_beta1.1.jar"

test in assembly := {}

mergeStrategy in assembly <<= (mergeStrategy in assembly) { (old) =>
  {
    case x if x.endsWith(".exe") => MergeStrategy.discard
    case PathList("importreports", xs @ _*) => MergeStrategy.discard
    case PathList("testfiles", xs @ _*) => MergeStrategy.discard
    case PathList("reports", xs @ _*) => MergeStrategy.discard
    case PathList("exportreports", xs @ _*) => MergeStrategy.discard
    case PathList("tinype", xs @ _*) => MergeStrategy.discard
    case PathList("yoda", xs @ _*) => MergeStrategy.discard
    case PathList("corkami", xs @ _*) => MergeStrategy.discard
    case PathList("unusualfiles", xs @ _*) => MergeStrategy.discard
    case PathList("x64viruses", xs @ _*) => MergeStrategy.discard
    case x => old(x)
  }
}

//mainClass in assembly := Some("com.github.katjahahn.tools.ReportCreator")
