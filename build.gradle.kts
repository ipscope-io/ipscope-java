plugins {
    `java-library`
    `maven-publish`
}

group = "io.ipscope"
version = "1.0.0"
description = "Official zero-dependency, type-safe Sync & Async Java 17+ Server-Side SDK for the IPScope IP Intelligence Platform."

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
