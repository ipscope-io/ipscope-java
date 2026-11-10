plugins {
    `java-library`
    `maven-publish`
}

group = "io.ipscope"
version = "1.1.0"
description = "Official zero-dependency, type-safe Sync & Async Java 17+ Server-Side SDK for the IPScope IP Intelligence Platform."

repositories {
    mavenCentral()
}

// Zero runtime dependencies; JUnit is test-only.
dependencies {
    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
    withSourcesJar()
    withJavadocJar()
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release.set(17)
}

tasks.test {
    useJUnitPlatform()
}
