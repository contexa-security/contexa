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
package io.contexa.autoconfigure.identity;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A table alias is not a table: in one SQL statement of the main sources, a {@code ctxa_} name used as a qualifier
 * ({@code ctxa_x.column}) must stand in a table position of the same statement (after from, join, update, into, using, ...).
 * <p>
 * The ctxa_ prefix was put on the table names of the SQL text by a rewrite; a table that is also used as an alias
 * ({@code ... from ctxa_prompt_governance_policy_set policy where policy.active = true}) must keep the alias as it is.
 * A rewrite that turned only the qualifiers into table names ({@code ctxa_policy.active}) leaves a statement the database
 * rejects with "missing FROM-clause entry", which no test that does not run that statement notices.
 */
class CtxaSqlAliasContractTest {

    private static final Pattern LITERAL = Pattern.compile("\"\"\"\\R(.*?)\"\"\"|\"((?:[^\"\\\\\\n]|\\\\.)*)\"", Pattern.DOTALL);
    private static final Pattern STATEMENT = Pattern.compile("^\\s*(select|insert|update|delete|with)\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern QUALIFIER = Pattern.compile("(?<![\\w.])(ctxa_[a-z0-9_]+)\\.(?=[a-z_])");
    private static final String POSITION = "(?:\\bfrom|\\bjoin|\\bupdate|\\binto|\\busing|\\bon\\s+constraint|\\bdelete\\s+from|"
            + "\\btable(?:\\s+if\\s+(?:not\\s+)?exists)?|\\bexists|\\btruncate(?:\\s+table)?|,)\\s+(?:only\\s+)?(?:public\\.)?";

    @Test
    void aCtxaNameUsedAsAQualifierIsATableOfItsStatement() throws IOException {
        Path root = repositoryRoot();
        List<String> violations = new ArrayList<>();
        try (Stream<Path> files = Files.walk(root)) {
            for (Path file : files.filter(CtxaSqlAliasContractTest::isMainJava).toList()) {
                String source = Files.readString(file, StandardCharsets.UTF_8).replace("\r\n", "\n");
                for (String statement : statements(source)) {
                    for (String name : qualifiers(statement)) {
                        if (!definedAsTable(statement, name)) {
                            violations.add(root.relativize(file).toString().replace('\\', '/') + ": " + name + " | "
                                    + statement.replaceAll("\\s+", " ").substring(0, Math.min(120, statement.replaceAll("\\s+", " ").length())));
                        }
                    }
                }
            }
        }
        assertThat(violations)
                .as("a ctxa_ qualifier that no table position of its statement defines is an alias the prefix rewrite turned into a table name")
                .isEmpty();
    }

    @Test
    void theCheckFindsAnAliasTurnedIntoATableName() {
        String broken = "select count(*) from ctxa_prompt_governance_policy_set policy where ctxa_policy.current_result = true";
        String sound = "select count(*) from ctxa_prompt_governance_policy_set policy where policy.current_result = true";
        String upsert = "insert into ctxa_agent_registration (id) values (?) on conflict (id) do update set seen = ctxa_agent_registration.seen";

        assertThat(qualifiers(broken)).containsExactly("ctxa_policy");
        assertThat(definedAsTable(broken, "ctxa_policy")).isFalse();
        assertThat(qualifiers(sound)).isEmpty();
        assertThat(definedAsTable(upsert, "ctxa_agent_registration")).as("the target of an upsert is a table of its statement").isTrue();
    }

    private static Set<String> qualifiers(String statement) {
        Set<String> names = new TreeSet<>();
        Matcher matcher = QUALIFIER.matcher(statement);
        while (matcher.find()) {
            names.add(matcher.group(1));
        }
        return names;
    }

    private static boolean definedAsTable(String statement, String name) {
        return Pattern.compile(POSITION + Pattern.quote(name) + "\\b", Pattern.CASE_INSENSITIVE).matcher(statement).find()
                || Pattern.compile(",\\s*" + Pattern.quote(name) + "\\b(?!\\.)", Pattern.CASE_INSENSITIVE).matcher(statement).find();
    }

    /** The SQL statements of a source: string literals and text blocks, literals joined by + counted as one. */
    private static List<String> statements(String source) {
        List<String> joined = new ArrayList<>();
        Matcher matcher = LITERAL.matcher(source);
        int previousEnd = -1;
        while (matcher.find()) {
            String body = matcher.group(1) != null ? matcher.group(1) : matcher.group(2);
            if (!joined.isEmpty() && previousEnd >= 0 && source.substring(previousEnd, matcher.start()).matches("\\s*\\+\\s*")) {
                joined.set(joined.size() - 1, joined.get(joined.size() - 1) + body);
            }
            else {
                joined.add(body);
            }
            previousEnd = matcher.end();
        }
        return joined.stream().filter(text -> STATEMENT.matcher(text).find()).toList();
    }

    private static boolean isMainJava(Path path) {
        String normalized = path.toString().replace('\\', '/');
        return Files.isRegularFile(path) && normalized.endsWith(".java") && normalized.contains("/src/main/")
                && !normalized.contains("/build/") && !normalized.contains("/.gradle/");
    }

    private static Path repositoryRoot() {
        Path current = Path.of("").toAbsolutePath().normalize();
        while (current != null) {
            if (Files.isDirectory(current.resolve("contexa-core")) && Files.isDirectory(current.resolve("contexa-autoconfigure"))) {
                return current;
            }
            current = current.getParent();
        }
        throw new IllegalStateException("the repository root (with contexa-core and contexa-autoconfigure) was not found above "
                + Path.of("").toAbsolutePath());
    }
}
