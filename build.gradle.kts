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

 val properties = Properties();
 var OSSRHstagingProfileId = ""
 var OSSRHusername = ""
 var OSSRHpassword = ""
 var signingPass = ""
 val file = File(rootProject.rootDir, "local.properties")
 if (file.exists()) {
     // Read local.properties file first if it exists
     properties.apply {
         load(FileInputStream(file))
     }
     OSSRHstagingProfileId = properties.getProperty("ossrh.stagingProfileId")
     OSSRHusername = properties.getProperty("ossrh.username")
     OSSRHpassword = properties.getProperty("ossrh.password")
 } else {
     println("here")
     // Use system environment variables
     OSSRHusername = System.getenv("OSSRH_USERNAME") ?: ""
     OSSRHpassword = System.getenv("OSSRH_PASSWORD") ?: ""
     OSSRHstagingProfileId = System.getenv("SONATYPE_STAGING_PROFILE_ID") ?: ""
     signingPass = System.getenv("SIGNING_PASSWORD") ?: ""
 }

 nexusPublishing {
     repositories {
         sonatype{
             nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
             stagingProfileId.set(OSSRHstagingProfileId)
             username.set(OSSRHusername)
             password.set(OSSRHpassword)
         }
     }
 }
