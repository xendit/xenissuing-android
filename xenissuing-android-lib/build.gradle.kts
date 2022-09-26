plugins {
    id("com.android.library")
    id("maven-publish")
    signing
    id("kotlin-android")
}

object AppProp {
    const val group = "com.xendit.xenissuing"
    const val version = "0.2.5"
}

version = AppProp.version
group = AppProp.group

object Meta {
    const val kotlinVersion = "1.3.70"
    const val targetSdkVersion = 32
    const val bintrayOrg = "xendit"
    const val bintrayRepo = "android"
    const val bintrayName = "xenissuing-android-lib"
    const val publishedGroupId = AppProp.group
    const val libraryName = "xenissuing-android"
    const val artifactId = "xenissuing-android-lib"
    const val libraryDescription = "The Xenissuing-android Android SDK makes for partner, in case to do decryption/encryption and generating session-id, so Brand Partner no need to worry about tech staff"
    const val siteUrl = "https://github.com/xendit/xenissuing-android"
    const val gitUrl = "https://github.com/xendit/xenissuing-android.git"
    const val libraryVersion = AppProp.version
    const val developerId = "jidi1f"
    const val developerName = "Danil Chernysh"
    const val developerEmail = "danylo-aimprosoft@xendit.co"
    const val licenseName = "MIT"
    const val licenseUrl = "https://opensource.org/licenses/MIT"
}

android {
    compileSdk =32
    defaultConfig {
        minSdk =21
        targetSdk =32

        consumerProguardFiles("proguard-rules.pro")
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

    }

    compileOptions {
       sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }

    testOptions {
        unitTests.all { test ->
            test.useJUnitPlatform()
        }
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])

                groupId = AppProp.group
                artifactId = Meta.artifactId
                version = AppProp.version

                pom {
                    name.set(Meta.bintrayName)
                    description.set(Meta.libraryDescription)
                    url.set(Meta.siteUrl)
                    packaging = "aar"
                    inceptionYear.set("2022")
                    licenses {
                        license {
                            name.set(Meta.licenseName)
                            url.set(Meta.licenseUrl)
                        }
                    }
                    developers {
                        developer {
                            id.set(Meta.developerId)
                            name.set(Meta.developerName)
                            email.set(Meta.developerEmail)
                        }
                    }
                    scm {
                        connection.set("scm:git:github.com/xendit/xenissuing-android.git")
                        developerConnection.set("scm:git:ssh://github.com/xendit/xenissuing-android.git")
                        url.set("https://github.com/github.com/xendit/xenissuing-android")
                    }
                }
            }
        }
    }

    signing {
        sign(publishing.publications["release"])
    }

}


dependencies {
    implementation ("org.bouncycastle:bcprov-jdk15on:1.70")
    implementation ("com.sun.mail:javax.mail:1.6.0")
    implementation ("commons-codec:commons-codec:1.15")
    implementation ("androidx.core:core-ktx:1.8.0")
    implementation ("commons-io:commons-io:2.6")
    implementation ("androidx.appcompat:appcompat:1.5.0")
    implementation ("com.google.android.material:material:1.6.1")
    implementation("io.mockk:mockk-android:1.10.0")
    implementation ("com.linkedin.dexmaker:dexmaker-mockito:2.28.3")
    implementation("com.android.support:support-annotations:28.0.0")
    testImplementation ("org.junit.jupiter:junit-jupiter-api:5.8.2")
    testImplementation ("io.kotlintest:kotlintest-runner-junit5:3.3.2")
    testRuntimeOnly ("org.junit.jupiter:junit-jupiter-engine:5.8.2")
    testRuntimeOnly ("org.junit.vintage:junit-vintage-engine:5.8.2")
    androidTestImplementation ("io.mockk:mockk-android:1.10.0")
}