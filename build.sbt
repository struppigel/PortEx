import SonatypeKeys._

name := "PortEx"

version := "3.0.0"

scalaVersion := "2.12.13"

javadocSettings

//add this if you have problems with invalid javadocs in Java 8
javacOptions in JavaDoc += "-Xdoclint:none"

sources in (JavaDoc, doc) ~= (_ filterNot (f => f.getName.contains("$") || f.getName.contains("Util") || f.getName.contains("ResourceDataEntry") || f.getName.contains("DirectoryEntry") || f.getName.contains("Scanning")))

libraryDependencies += "org.testng" % "testng" % "6.8.8" % "test"

libraryDependencies += "com.google.guava" % "guava" % "17.0"

libraryDependencies += "com.google.code.findbugs" % "jsr305" % "2.0.2"

libraryDependencies += "org.apache.logging.log4j" % "log4j-api" % "2.14.1"

libraryDependencies += "org.apache.logging.log4j" % "log4j-core" % "2.14.1"

// Import default settings. This changes `publishTo` settings to use the Sonatype repository and add several commands for publishing.
sonatypeSettings

// Your project organization (package name)
organization := "com.github.katjahahn"

// To sync with Maven central, you need to supply the following information:
pomExtra := {
  <url>https://github.com/katjahahn/PortEx</url>
  <licenses>
    <license>
      <name>Apache 2</name>
      <url>http://www.apache.org/licenses/LICENSE-2.0.txt</url>
    </license>
  </licenses>
  <scm>
    <connection>scm:katjahahn/PortEx.git</connection>
    <developerConnection>scm:git:git@github.com:katjahahn/PortEx.git</developerConnection>
    <url>github.com/katjahahn/PortEx</url>
  </scm>
  <developers>
    <developer>
      <id>katjahahn</id>
      <name>Katja Hahn</name>
      <url>https://github.com/katjahahn/PortEx</url>
    </developer>
  </developers>
}
