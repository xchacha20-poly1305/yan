import java.net.URI
import org.gradle.api.tasks.bundling.AbstractArchiveTask
import org.gradle.jvm.tasks.Jar
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.dokka)
    alias(libs.plugins.maven.publish)
    alias(libs.plugins.android.library) apply false
    `java-library`
}

dokka {
    dokkaPublications.named("html") {
        moduleVersion.set(providers.gradleProperty("VERSION_NAME"))
    }

    val sourceRef = providers.environmentVariable("GITHUB_SHA").orElse("dev")
    dokkaSourceSets.named("main") {
        includes.from("README.md")
        sourceLink {
            localDirectory.set(layout.projectDirectory.dir("src/main/kotlin"))
            remoteUrl.set(sourceRef.map { ref ->
                URI("https://github.com/xchacha20-poly1305/yan/blob/$ref/src/main/kotlin")
            })
            remoteLineSuffix.set("#L")
        }
    }
}

val projectLicense = layout.projectDirectory.file("LICENSE")

allprojects {
    tasks.withType<AbstractArchiveTask>().configureEach {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
    }
}

tasks.withType<Jar>().configureEach {
    from(projectLicense) {
        into("META-INF")
    }
}

kotlin {
    explicitApi()
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_1_8)
        freeCompilerArgs.add("-Xjdk-release=8")
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    implementation(libs.bcprov)
    testImplementation(libs.junit)
    testImplementation(libs.kotlin.test.junit)
}

tasks.test {
    useJUnit()
    maxHeapSize = "2g"
}

mavenPublishing {
    publishToMavenCentral()
    signAllPublications()
}
