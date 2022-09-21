 // Top-level build file where you can add configuration options common to all sub-projects/modules.
 import java.io.File
 import java.io.FileInputStream
 import java.util.*

 plugins {
     id ("com.android.library") version "7.2.1" apply false;
     id ("org.jetbrains.kotlin.android") version "1.6.10" apply false;
     id("io.github.gradle-nexus.publish-plugin") version "1.1.0"
 }


 tasks.register("clean").configure {
    delete(rootProject.buildDir)
}

 val properties = Properties().apply {
     load(FileInputStream(File(rootProject.rootDir, "gradle.properties")))
 }

 nexusPublishing {
     repositories {
         sonatype{
             nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
             stagingProfileId.set(properties.getProperty("ossrh.stagingProfileId"))
             username.set(properties.getProperty("ossrh.username"))
             password.set(properties.getProperty("ossrh.password"))
         }
     }
 }
