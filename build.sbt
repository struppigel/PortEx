name := "PortEx"

version := "0.1"

javadocSettings

libraryDependencies += "com.kanishka.api" % "VirustotalPublicV2.0" % "1.1.GA"

resolvers += "Local Maven Repository" at "file://"+Path.userHome.absolutePath+"/.m2/repository"
