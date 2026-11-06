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
package io.contexa.contexaiam.security.xacml.pdp.evaluation;

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

/**
 * A name reaches a policy expression only as a literal written by {@link SpelLiteral}, and a literal is read back only
 * the way {@link SpelLiteral} reads it. The source is read, since a new place that joins a name into an expression is
 * what this guards against.
 */
class PolicyExpressionLiteralGuardTest {

    private static final Path SOURCES = Path.of("src/main/java");
    private static final String SPEL_LITERAL = "SpelLiteral.java";

    /** A call of the expression language whose literal is opened by hand and filled by a format or a join. */
    private static final Pattern CALL_FILLED_BY_A_VALUE = Pattern.compile(
            "\\b(?:hasAuthority|hasAnyAuthority|hasRole|hasAnyRole|hasPermission|hasIpAddress|hasAction|hasActionIn|hasActionOrDefault)"
                    + "\\('(?:%s|\"\\s*\\+)");
    /** A quote joined to a value, the way a literal used to be written by hand. */
    private static final Pattern QUOTE_JOINED = Pattern.compile("\"'\"\\s*\\+|\\+\\s*\"'\"");
    /** A literal read as "anything but a quote", which stops at the first quote of a doubled one. */
    private static final Pattern LITERAL_READ_BY_HAND = Pattern.compile("\\[\\^'");

    /** Where policy expressions are written; messages elsewhere quote names for people to read. */
    private static final List<String> EXPRESSION_WRITERS = List.of(
            "security/xacml/pap/", "security/xacml/pdp/translator/", "admin/web/center/");

    @Test
    @DisplayName("no expression call is filled with a value by a format or a join")
    void noCallIsFilledWithAValue() throws IOException {
        assertThat(find(CALL_FILLED_BY_A_VALUE, List.of(""))).isEmpty();
    }

    @Test
    @DisplayName("no literal is written by joining quotes to a value where expressions are written")
    void noLiteralIsWrittenByHand() throws IOException {
        assertThat(find(QUOTE_JOINED, EXPRESSION_WRITERS)).isEmpty();
    }

    @Test
    @DisplayName("no literal is read as anything up to the first quote")
    void noLiteralIsReadByHand() throws IOException {
        assertThat(find(LITERAL_READ_BY_HAND, List.of(""))).isEmpty();
    }

    private static List<String> find(Pattern pattern, List<String> under) throws IOException {
        List<String> found = new ArrayList<>();
        try (Stream<Path> files = Files.walk(SOURCES)) {
            for (Path file : files.filter(f -> f.toString().endsWith(".java")).toList()) {
                String path = file.toString().replace('\\', '/');
                if (file.getFileName().toString().equals(SPEL_LITERAL) || under.stream().noneMatch(path::contains)) {
                    continue;
                }
                List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
                for (int i = 0; i < lines.size(); i++) {
                    Matcher matcher = pattern.matcher(lines.get(i));
                    if (matcher.find()) {
                        found.add(file.getFileName() + ":" + (i + 1) + " " + lines.get(i).strip());
                    }
                }
            }
        }
        return found;
    }
}
