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
package io.contexa.autoconfigure.iam.admin;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The controller answered at /contexa/password-change from its first commit on, while two failure handlers and two pages
 * pointed at /password-change and the page's way back at /contexa/admin/mfa/login, neither of which anything answers.
 * Each side's own test passed.
 */
class ContexaConsolePathsContractTest {

    private static final List<String> NOTHING_ANSWERS_THESE = List.of(
            "\"/password-change", "@{/password-change", "/contexa/admin/mfa/login");

    @Test
    @DisplayName("nothing points at a console path that nothing answers")
    void noDeadConsolePaths() throws IOException {
        Path root = Path.of("").toAbsolutePath().getParent();
        List<String> dead = new ArrayList<>();
        int read = 0;
        try (Stream<Path> files = Files.walk(root)) {
            for (Path file : files.filter(ContexaConsolePathsContractTest::isMainSource).toList()) {
                read++;
                String text = Files.readString(file, StandardCharsets.UTF_8);
                for (String path : NOTHING_ANSWERS_THESE) {
                    if (text.contains(path)) {
                        dead.add(root.relativize(file) + " -> " + path);
                    }
                }
            }
        }
        assertThat(read).as("the sources were found").isGreaterThan(1500);
        assertThat(dead).isEmpty();
    }

    /** An application's GrantedAuthorityDefaults gives hasRole another prefix, and Contexa's administrators lose the console. */
    @Test
    @DisplayName("Contexa's own authorization does not depend on the role prefix of the application")
    void noRolePrefixOfTheApplicationInContexasAuthorization() throws IOException {
        Path root = Path.of("").toAbsolutePath().getParent();
        List<String> found = new ArrayList<>();
        try (Stream<Path> files = Files.walk(root)) {
            for (Path file : files.filter(ContexaConsolePathsContractTest::isMainSource).toList()) {
                for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                    boolean authorizes = line.contains("@PreAuthorize(") || line.contains("sec:authorize=");
                    boolean byRole = line.contains("hasRole(") || line.contains("hasAnyRole(");
                    if ((authorizes && byRole) || line.contains(".hasRole(\"") || line.contains(".hasAnyRole(\"")) {
                        found.add(root.relativize(file) + " -> " + line.trim());
                    }
                }
            }
        }
        assertThat(found).isEmpty();
    }

    private static boolean isMainSource(Path file) {
        String name = file.toString().replace('\\', '/');
        return name.contains("/src/main/") && !name.contains("/build/")
                && (name.endsWith(".java") || name.endsWith(".html") || name.endsWith(".js"));
    }
}
