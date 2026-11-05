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
package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/** Q-18: every spelling an application takes for one name reads one key. */
class ZeroTrustUserKeyTest {

    @ParameterizedTest
    @ValueSource(strings = {"plain-k9", "PLAIN-K9", "Plain-K9", "ｐlain-k9", "ＰＬＡＩＮ－Ｋ９",
            " plain-k9", "plain-k9 ", "　plain-k9　", "plain－k9"})
    @DisplayName("capitals, full-width letters and surrounding spaces are one name")
    void spellingsOfOneName(String spelling) {
        assertThat(ZeroTrustUserKey.of(spelling)).isEqualTo("plain-k9");
    }

    @Test
    @DisplayName("names that differ in more than the spelling stay apart")
    void differentNamesStayApart() {
        assertThat(ZeroTrustUserKey.of("plain-k9")).isNotEqualTo(ZeroTrustUserKey.of("plain-k8"));
        assertThat(ZeroTrustUserKey.of("김철수")).isEqualTo("김철수");
    }

    @Test
    @DisplayName("case folding follows no locale of the JVM")
    void noLocaleOfTheJvm() {
        Locale before = Locale.getDefault();
        Locale.setDefault(Locale.forLanguageTag("tr-TR"));
        try {
            assertThat(ZeroTrustUserKey.of("ADMIN-I")).isEqualTo("admin-i");
        } finally {
            Locale.setDefault(before);
        }
    }

    @Test
    @DisplayName("a key is its own key, so a store may meet it twice")
    void aKeyIsItsOwnKey() {
        String key = ZeroTrustUserKey.of("Straße１");
        assertThat(ZeroTrustUserKey.of(key)).isEqualTo(key);
    }

    @Test
    @DisplayName("null and a blank name pass through for the stores to refuse")
    void nullAndBlank() {
        assertThat(ZeroTrustUserKey.of(null)).isNull();
        assertThat(ZeroTrustUserKey.of("   ")).isBlank();
    }

    @ParameterizedTest
    @ValueSource(strings = {"console::admin", "CONSOLE::ADMIN", "Console::Admin", "ｃｏｎｓｏｌｅ::admin",
            " console::admin ", "　console::admin　", "console：：admin", "conſole::admin",
            "alice::agent::bot", "ALICE::AGENT::BOT", "ａｌｉｃｅ::agent::bot", " alice::agent::bot ",
            "alice：：agent：：bot", "::agent::bot", "alice::agent::"})
    @DisplayName("a name in the form of an internal key never reads the key of a console session or an agent")
    void aNameNeverReachesAnInternalKey(String name) {
        String key = ZeroTrustUserKey.of(ZeroTrustUserKey.person(name));

        assertThat(key).doesNotStartWith("console::").doesNotContain("::agent::");
    }

    @ParameterizedTest
    @ValueSource(strings = {"plain-k9", "PLAIN-K9", " bob ", "김철수", "a::b", "console", "agent", "consoleuser",
            "console:admin", "user@example.com", "DOMAIN\\user", "bot::7"})
    @DisplayName("every other name keeps its key, so what is stored under it stays")
    void anOrdinaryNameKeepsItsKey(String name) {
        assertThat(ZeroTrustUserKey.person(name)).isEqualTo(name);
    }

    @ParameterizedTest
    @ValueSource(strings = {"CONSOLE::ADMIN", "ｃｏｎｓｏｌｅ::admin", " console::admin ", "console：：admin"})
    @DisplayName("the spellings of such a name are one name")
    void spellingsOfAMovedName(String spelling) {
        assertThat(ZeroTrustUserKey.person(spelling)).isEqualTo(ZeroTrustUserKey.person("console::admin"));
    }

    @Test
    @DisplayName("names that differ stay apart, the key of a moved name included")
    void movedNamesStayApart() {
        String moved = ZeroTrustUserKey.person("console::admin");

        assertThat(moved).isNotEqualTo(ZeroTrustUserKey.person("console::admin2"));
        assertThat(moved).isNotEqualTo(ZeroTrustUserKey.person("alice::agent::admin"));
        assertThat(ZeroTrustUserKey.person(moved)).as("a name spelled as such a key is a name too").isNotEqualTo(moved);
        assertThat(ZeroTrustUserKey.person("console::a:b")).isNotEqualTo(ZeroTrustUserKey.person("console::a%003ab"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"console::admin", "console::김철수", "alice::agent::Σίσυφος", "console::Straße１"})
    @DisplayName("the key of a moved name is its own key, so a store may meet it twice")
    void aMovedKeyIsItsOwnKey(String name) {
        String key = ZeroTrustUserKey.person(name);

        assertThat(key).isNotEqualTo(name);
        assertThat(ZeroTrustUserKey.of(key)).isEqualTo(key);
    }

    @Test
    @DisplayName("null and a blank name pass through for the stores to refuse")
    void nullAndBlankAsAPerson() {
        assertThat(ZeroTrustUserKey.person(null)).isNull();
        assertThat(ZeroTrustUserKey.person("   ")).isBlank();
    }

    @Test
    @DisplayName("names told apart by case stay apart when the setting is off, and off the internal keys")
    void movedNamesWithTheSettingOff() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.setNormalizeUserKeys(false);
        ZeroTrustUserKey.bind(properties);
        try {
            assertThat(ZeroTrustUserKey.person("console::Admin")).doesNotStartWith("console::");
            assertThat(ZeroTrustUserKey.person("Console::Admin")).isNotEqualTo(ZeroTrustUserKey.person("console::admin"));
            assertThat(ZeroTrustUserKey.of(ZeroTrustUserKey.person("Plain-K9"))).isEqualTo("Plain-K9");
        } finally {
            ZeroTrustUserKey.unbind(properties);
        }
    }

    @Test
    @DisplayName("an application whose names differ by case turns it off")
    void theSetting() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.setNormalizeUserKeys(false);
        ZeroTrustUserKey.bind(properties);
        try {
            assertThat(ZeroTrustUserKey.of("Plain-K9")).isEqualTo("Plain-K9");
        } finally {
            ZeroTrustUserKey.unbind(properties);
        }
        assertThat(ZeroTrustUserKey.of("Plain-K9")).isEqualTo("plain-k9");
    }
}
