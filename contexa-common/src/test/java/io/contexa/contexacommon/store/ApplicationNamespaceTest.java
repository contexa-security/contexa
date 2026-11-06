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
package io.contexa.contexacommon.store;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** What names an application's keys and its consumer group: nothing without a name, one prefix with it. */
class ApplicationNamespaceTest {

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t\n"})
    @DisplayName("a missing or blank name leaves the application without one, and every key as it was")
    void withoutAName(String name) {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(name)) {
            assertThat(ApplicationNamespace.isNamed()).isFalse();
            assertThat(ApplicationNamespace.identifier()).isEmpty();
            assertThat(ApplicationNamespace.key("security:blocked:users:alice")).isEqualTo("security:blocked:users:alice");
            assertThat(ApplicationNamespace.key("threat_score:alice")).isEqualTo("threat_score:alice");
            assertThat(ApplicationNamespace.consumerGroup("security-plane-consumer")).isEqualTo("security-plane-consumer");
        }
    }

    @Test
    @DisplayName("a name puts ctxa:<name>: before the key the application always had, and .<name> after the group")
    void withAName() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("petclinic-a")) {
            assertThat(ApplicationNamespace.isNamed()).isTrue();
            assertThat(ApplicationNamespace.identifier()).isEqualTo("petclinic-a");
            assertThat(ApplicationNamespace.key("security:blocked:users:alice"))
                    .isEqualTo("ctxa:petclinic-a:security:blocked:users:alice");
            assertThat(ApplicationNamespace.key("threat_score:alice")).isEqualTo("ctxa:petclinic-a:threat_score:alice");
            assertThat(ApplicationNamespace.consumerGroup("security-plane-consumer"))
                    .isEqualTo("security-plane-consumer.petclinic-a");
        }
    }

    @Test
    @DisplayName("the name is lower case: the name of the servers of one application is the same however it is cased")
    void lowerCase() {
        assertThat(ApplicationNamespace.normalize("PetClinic-A")).isEqualTo("petclinic-a");
        assertThat(ApplicationNamespace.normalize("  petclinic.a_1  ")).isEqualTo("petclinic.a_1");
    }

    @Test
    @DisplayName("every other character is escaped to its bytes, so ':' and the glob characters never enter the prefix")
    void escapes() {
        assertThat(ApplicationNamespace.normalize("my app")).isEqualTo("my~20app");
        assertThat(ApplicationNamespace.normalize("a:b")).isEqualTo("a~3ab");
        assertThat(ApplicationNamespace.normalize("a*b?c[d]e\\f")).isEqualTo("a~2ab~3fc~5bd~5de~5cf");
        assertThat(ApplicationNamespace.normalize("a~b")).isEqualTo("a~7eb");
        assertThat(ApplicationNamespace.normalize("한")).isEqualTo("~ed~95~9c");
    }

    @Test
    @DisplayName("names that differ do not become one name, and the prefix holds no glob character or colon of its own")
    void differentNamesStayDifferent() {
        String[] names = {"a", "a-b", "a.b", "a_b", "a:b", "a b", "a*b", "a?b", "a[b", "a]b", "a\\b", "a~b", "a~20b",
                "한글", "é", "e", "app", "app1", "app-1", "ctxa", "ctxa:a"};
        Set<String> seen = new HashSet<>();
        for (String name : names) {
            String identifier = ApplicationNamespace.normalize(name);
            assertThat(identifier).matches("[a-z0-9._~-]+");
            assertThat(seen.add(identifier)).as("%s became %s, which another name has too", name, identifier).isTrue();
            try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(name)) {
                String key = ApplicationNamespace.key("");
                assertThat(key).startsWith("ctxa:").endsWith(":");
                assertThat(key.substring("ctxa:".length(), key.length() - 1)).doesNotContain(":", "*", "?", "[", "]", "\\");
            }
        }
    }

    @Test
    @DisplayName("a name that is too long is cut to the limit and ends in a digest of the whole, so two long names differ")
    void longNames() {
        String common = "an-application-name-that-is-much-longer-than-the-limit-of-the-identifier";
        String first = ApplicationNamespace.normalize(common + "-one");
        String second = ApplicationNamespace.normalize(common + "-two");

        assertThat(first).hasSize(ApplicationNamespace.MAX_IDENTIFIER_LENGTH);
        assertThat(second).hasSize(ApplicationNamespace.MAX_IDENTIFIER_LENGTH);
        assertThat(first).isNotEqualTo(second);
        assertThat(first).isEqualTo(ApplicationNamespace.normalize(common + "-one"));
        assertThat(first).matches("[a-z0-9._~-]+");
        assertThat(ApplicationNamespace.normalize("x".repeat(ApplicationNamespace.MAX_IDENTIFIER_LENGTH)))
                .isEqualTo("x".repeat(ApplicationNamespace.MAX_IDENTIFIER_LENGTH));
    }

    @Test
    @DisplayName("a scope restores what was bound before it, so a process running several applications in turn is not mixed up")
    void scopeRestores() {
        try (ApplicationNamespace.Scope outer = ApplicationNamespace.using("outer")) {
            try (ApplicationNamespace.Scope inner = ApplicationNamespace.using("inner")) {
                assertThat(ApplicationNamespace.identifier()).isEqualTo("inner");
            }
            assertThat(ApplicationNamespace.identifier()).isEqualTo("outer");
        }
        assertThat(ApplicationNamespace.isNamed()).isFalse();
    }

    @Test
    @DisplayName("configure binds the name once and a blank name unbinds it")
    void configure() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(null)) {
            ApplicationNamespace.configure("Shop");
            assertThat(ApplicationNamespace.identifier()).isEqualTo("shop");
            ApplicationNamespace.configure("");
            assertThat(ApplicationNamespace.isNamed()).isFalse();
        }
    }
}
