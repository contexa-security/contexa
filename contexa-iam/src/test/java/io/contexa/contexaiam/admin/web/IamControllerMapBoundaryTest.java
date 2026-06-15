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
package io.contexa.contexaiam.admin.web;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("IAM controller Map boundary")
class IamControllerMapBoundaryTest {

    private static final Pattern DISALLOWED_MAP_USAGE = Pattern.compile(
            "\\bResponseEntity\\s*<\\s*(?:java\\.util\\.)?Map\\b"
                    + "|\\b(?:java\\.util\\.)?Map\\s*<"
                    + "|\\bList\\s*<\\s*(?:java\\.util\\.)?Map\\b"
                    + "|\\bnew\\s+HashMap\\b"
                    + "|\\bnew\\s+LinkedHashMap\\b"
                    + "|\\bMap\\.of\\s*\\("
                    + "|\\bimport\\s+java\\.util\\.Map\\s*;"
                    + "|\\bMap\\b");

    @Test
    @DisplayName("IAM controllers do not build response or model payloads with Map")
    void iamControllersDoNotBuildResponseOrModelPayloadsWithMap() throws IOException {
        Path iamSourceRoot = resolveIamSourceRoot();
        List<Path> controllerFiles = findControllerFiles(iamSourceRoot);

        assertThat(controllerFiles).isNotEmpty();

        List<String> violations = new ArrayList<>();
        for (Path controllerFile : controllerFiles) {
            violations.addAll(findViolations(iamSourceRoot, controllerFile));
        }

        assertThat(violations).isEmpty();
    }

    private static Path resolveIamSourceRoot() {
        Path moduleRelative = Path.of("src/main/java/io/contexa/contexaiam")
                .toAbsolutePath()
                .normalize();
        if (Files.isDirectory(moduleRelative)) {
            return moduleRelative;
        }

        Path repoRelative = Path.of("contexa-iam/src/main/java/io/contexa/contexaiam")
                .toAbsolutePath()
                .normalize();
        if (Files.isDirectory(repoRelative)) {
            return repoRelative;
        }

        throw new IllegalStateException("Cannot resolve contexa-iam source root");
    }

    private static List<Path> findControllerFiles(Path adminSourceRoot) throws IOException {
        try (Stream<Path> paths = Files.walk(adminSourceRoot)) {
            return paths
                    .filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().endsWith("Controller.java"))
                    .filter(path -> !path.toString().contains("promptquality/official") 
                            && !path.toString().contains("promptquality\\official"))
                    .sorted()
                    .toList();
        }
    }

    private static List<String> findViolations(Path adminSourceRoot, Path controllerFile) throws IOException {
        String source = Files.readString(controllerFile, StandardCharsets.UTF_8);
        Matcher matcher = DISALLOWED_MAP_USAGE.matcher(source);
        List<String> violations = new ArrayList<>();

        while (matcher.find()) {
            violations.add(adminSourceRoot.relativize(controllerFile)
                    + ":" + lineNumber(source, matcher.start())
                    + " -> " + matcher.group());
        }

        return violations;
    }

    private static long lineNumber(String source, int offset) {
        return source.substring(0, offset)
                .chars()
                .filter(character -> character == '\n')
                .count() + 1;
    }
}
