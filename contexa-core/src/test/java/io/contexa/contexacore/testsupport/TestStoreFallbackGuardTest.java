/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.testsupport;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The tests of every module find their Redis and their database through {@code TestStores} only. A test that falls back
 * to an address of its own reaches the Redis or the database of the developer who runs it without the variables.
 */
class TestStoreFallbackGuardTest {

    /** A lookup with a fallback, the variables of the application itself, and the password of the compose database. */
    private static final List<String> FALLBACKS = List.of(
            "getOrDefault(\"CONTEXA_",
            "\"CONTEXA_DB_URL\"",
            "\"CONTEXA_DB_USERNAME\"",
            "\"CONTEXA_DB_PASSWORD\"",
            "\"contexa1234!@#\"");

    @Test
    @DisplayName("no test falls back to a Redis or a database of its own when the variables are not set")
    void noTestFallsBackToAStoreOfItsOwn() throws IOException {
        Path root = repositoryRoot();
        List<String> found = new ArrayList<>();
        for (Path source : testSources(root)) {
            List<String> lines = Files.readAllLines(source, StandardCharsets.UTF_8);
            for (int index = 0; index < lines.size(); index++) {
                String line = lines.get(index);
                if (FALLBACKS.stream().anyMatch(line::contains)) {
                    found.add(root.relativize(source) + ":" + (index + 1) + ": " + line.trim());
                }
            }
        }

        assertThat(found).as("read CONTEXA_TEST_* through TestStores, which skips the test when they are not set")
                .isEmpty();
    }

    @Test
    @DisplayName("a test that empties its Redis takes it from TestStores.disposableRedis(), which refuses port 6379")
    void aTestThatEmptiesItsRedisRefusesTheUsualPortOfADeveloperRedis() throws IOException {
        Path root = repositoryRoot();
        List<String> found = new ArrayList<>();
        for (Path source : testSources(root)) {
            String text = Files.readString(source, StandardCharsets.UTF_8);
            boolean empties = text.contains("flushDb()") || text.contains("flushAll()");
            if (empties && !text.contains("TestStores.disposableRedis()")) {
                found.add(root.relativize(source).toString());
            }
        }

        assertThat(found).as("tests that run FLUSHDB or FLUSHALL").isEmpty();
    }

    private static List<Path> testSources(Path root) throws IOException {
        List<Path> sources = new ArrayList<>();
        try (Stream<Path> modules = Files.list(root)) {
            for (Path module : modules.filter(path -> Files.isRegularFile(path.resolve("build.gradle"))).toList()) {
                for (String sourceSet : List.of("test", "testFixtures")) {
                    Path java = module.resolve("src").resolve(sourceSet).resolve("java");
                    if (!Files.isDirectory(java)) {
                        continue;
                    }
                    try (Stream<Path> files = Files.walk(java)) {
                        files.filter(path -> path.toString().endsWith(".java"))
                                .filter(path -> !path.getFileName().toString().equals("TestStoreFallbackGuardTest.java"))
                                .forEach(sources::add);
                    }
                }
            }
        }
        assertThat(sources).as("test sources found under " + root).isNotEmpty();
        return sources;
    }

    /** The directory that holds the modules; each module has a settings.gradle of its own, so that is no mark. */
    private static Path repositoryRoot() {
        Path directory = Path.of("").toAbsolutePath();
        while (directory != null && !Files.isRegularFile(directory.resolve("contexa-core").resolve("build.gradle"))) {
            directory = directory.getParent();
        }
        assertThat(directory).as("the directory of the modules above the working directory").isNotNull();
        return directory;
    }
}
