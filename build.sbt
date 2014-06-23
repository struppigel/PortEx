name := "PortEx"

version := "0.6.0"

javadocSettings

sources in (JavaDoc, doc) ~= (_ filterNot (f => f.getName.contains("$") || f.getName.contains("Util") || f.getName.contains("Scanning")))

libraryDependencies += "com.google.java.contract" % "cofoja" % "1.1-r150"

libraryDependencies += "org.testng" % "testng" % "6.8.8" % "test"

libraryDependencies += "com.google.guava" % "guava" % "17.0"

libraryDependencies += "com.google.code.findbugs" % "jsr305" % "2.0.2"

libraryDependencies += "org.apache.logging.log4j" % "log4j-api" % "2.0-rc1"

libraryDependencies += "org.apache.logging.log4j" % "log4j-core" % "2.0-rc1"
