import SonatypeKeys._

name := "PortEx"

version := "3.0.3"

scalaVersion := "2.12.13"

javadocSettings

//add this if you have problems with invalid javadocs in Java 8
javacOptions in JavaDoc += "-Xdoclint:none"

sources in (JavaDoc, doc) ~= (_ filterNot (f => f.getName.contains("$") || f.getName.contains("Util") || f.getName.contains("ResourceDataEntry") || f.getName.contains("DirectoryEntry") || f.getName.contains("Scanning")))

libraryDependencies += "org.testng" % "testng" % "6.8.8" % "test"

libraryDependencies += "com.google.guava" % "guava" % "31.0.1-jre"

libraryDependencies += "com.google.code.findbugs" % "jsr305" % "3.0.2"

libraryDependencies += "org.apache.logging.log4j" % "log4j-api" % "2.16.0"

libraryDependencies += "org.apache.logging.log4j" % "log4j-core" % "2.16.0"

// Import default settings. This changes `publishTo` settings to use the Sonatype repository and add several commands for publishing.
sonatypeSettings

// Your project organization (package name)
organization := "com.github.katjahahn"

pomIncludeRepository := { _ => false }

publishTo := {
  val nexus = "https://oss.sonatype.org/"
  if (isSnapshot.value) Some("snapshots" at nexus + "content/repositories/snapshots")
  else Some("releases" at nexus + "service/local/staging/deploy/maven2")
}

scmInfo := Some(
  ScmInfo(
    url("https://github.com/katjahahn/PortEx.git"),
    "scm:git@github.com:katjahahn/PortEx.git"
  )
)

developers := List(
  Developer(
    id    = "struppigel",
    name  = "Karsten Hahn",
    email = "struppigel@googlemail.com",
    url   = url("https://github.com/katjahahn/PortEx")
  )
)

licenses := List("Apache 2" -> new URL("http://www.apache.org/licenses/LICENSE-2.0.txt"))

description := "Java library to parse Portable Executable files"

homepage := Some(url("https://github.com/katjahahn/PortEx"))

publishMavenStyle := true