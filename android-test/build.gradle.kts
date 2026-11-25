plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "io.github.xchacha20_poly1305.yan.androidtest"
    compileSdk = 37

    defaultConfig {
        minSdk = 21
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    sourceSets.getByName("androidTest").assets.srcDir(
        rootProject.layout.projectDirectory.dir("src/test/resources/cctv"),
    )
}

// AGP compiles with its built-in Kotlin, older than the root library's Kotlin; raise it to read its metadata.
configurations.matching { it.name in setOf("kotlinCompilerClasspath", "kotlinBuildToolsApiClasspath") }
    .configureEach {
        resolutionStrategy.eachDependency {
            if (requested.group == "org.jetbrains.kotlin") {
                useVersion(libs.versions.kotlin.get())
            }
        }
    }

dependencies {
    implementation(project(":"))

    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.kotlin.test.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
