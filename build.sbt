name := "PortEx"

version := "5.0.7-SNAPSHOT"

scalaVersion := "2.12.13"

assembly / assemblyJarName := "PortexAnalyzer.jar"

assembly / mainClass := Some("io.github.struppigel.tools.PortExAnalyzer")

assembly / assemblyMergeStrategy := {
  case PathList("META-INF", "versions", "9", "module-info.class") =>
    MergeStrategy.discard

  case PathList("META-INF", "MANIFEST.MF") =>
    MergeStrategy.discard // assembly will write its own

  case PathList("META-INF", xs @ _*) if xs.exists(_.toLowerCase.endsWith(".sf")) =>
    MergeStrategy.discard

  case PathList("META-INF", xs @ _*) if xs.exists(_.toLowerCase.endsWith(".rsa")) =>
    MergeStrategy.discard

  case PathList("META-INF", xs @ _*) =>
    MergeStrategy.first

  case x =>
    (assembly / assemblyMergeStrategy).value(x)
}


lazy val JavaDoc = config("genjavadoc") extend Compile

lazy val javadocSettings = inConfig(JavaDoc)(Defaults.configSettings) ++ Seq(
  addCompilerPlugin("com.typesafe.genjavadoc" %% "genjavadoc-plugin" % "0.18_2.13.10" cross CrossVersion.full),
  scalacOptions += s"-P:genjavadoc:out=${target.value}/java",
  Compile / packageDoc := (JavaDoc / packageDoc).value,
  JavaDoc / sources :=
    (target.value / "java" ** "*.java").get ++
      (Compile / sources).value.filter(_.getName.endsWith(".java")),
  JavaDoc / javacOptions := Seq("-Xdoclint:none"),
  JavaDoc / packageDoc / artifactName := ((sv, mod, art) =>
    "" + mod.name + "_" + sv.binary + "-" + mod.revision + "-javadoc.jar")
)

lazy val root = project.in(file(".")).configs(JavaDoc).settings(javadocSettings: _*)

libraryDependencies += "org.testng" % "testng" % "7.11.0" % "test"

libraryDependencies += "com.google.guava" % "guava" % "33.4.8-jre"

libraryDependencies += "com.google.code.findbugs" % "jsr305" % "3.0.2" % "provided"

libraryDependencies += "org.apache.logging.log4j" % "log4j-api" % "2.23.1"

// libraryDependencies += "org.apache.logging.log4j" % "log4j-core" % "2.23.1"

// Your project organization (package name)
organization := "io.github.struppigel"

pomIncludeRepository := { _ => false }

publishMavenStyle := true
githubOwner := "struppigel"
githubRepository := "PortEx"
credentials += Credentials(
  "Sonatype Package Registry",
  "central.sonatype.com",
  "struppigel",
  System.getenv("GITHUB_TOKEN")
)

scmInfo := Some(
  ScmInfo(
    url("https://github.com/struppigel/PortEx.git"),
    "scm:git@github.com:struppigel/PortEx.git"
  )
)

developers := List(
  Developer(
    id    = "struppigel",
    name  = "Karsten Hahn",
    email = "struppigel@googlemail.com",
    url   = url("https://github.com/struppigel/PortEx")
  )
)

description := "Java library to parse Portable Executable files"
licenses := List(
  "Apache 2" -> new URL("http://www.apache.org/licenses/LICENSE-2.0.txt")
)
homepage := Some(url("https://github.com/struppigel/PortEx"))

publishTo := {
  val centralSnapshots = "https://central.sonatype.com/repository/maven-snapshots/"
  if (isSnapshot.value) Some("central-snapshots" at centralSnapshots)
  else localStaging.value
}

versionScheme := Some("early-semver") // meaning: major.minor.patch version scheme


Global / onChangedBuildSource := ReloadOnSourceChanges