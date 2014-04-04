name := "PortEx"

version := "0.1"

javadocSettings

libraryDependencies += "com.kanishka.api" % "VirustotalPublicV2.0" % "1.1.GA"

libraryDependencies += "org.testng" % "testng" % "6.8.8" % "test"

libraryDependencies += "org.apache.logging.log4j" % "log4j-api" % "2.0-rc1"

libraryDependencies += "org.apache.logging.log4j" % "log4j-core" % "2.0-rc1"

//libraryDependencies += "org.jclarion" % "image4j" % "0.7"

resolvers += "Local Maven Repository" at "file://"+Path.userHome.absolutePath+"/.m2/repository"
