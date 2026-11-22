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
package io.contexa.contexaiam.admin.promptquality.screen;

import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityNav.Tab;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityScreens.Count;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityScreens.Menu;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Quality plan 3.8: the menu bar of the prompt quality assurance group is defined in one place; a page's bar lists
 * its menus in that order with their counts in the reader's language, reads the counts once and only when drawn, and
 * keeps the scope of the page. Every word of the bar and of the menus is in both languages and translated.
 */
class PromptQualityNavTest {

    @Test
    void theBarHasTheFiveMenusInThePlansOrder() {
        assertThat(PromptQualityScreens.MENUS).extracting(Menu::key)
                .containsExactly("status", "cases", "measure", "versions", "evidence");
        assertThat(PromptQualityScreens.MENUS).extracting(Menu::path).containsExactly(PromptQualityScreens.STATUS,
                PromptQualityScreens.CASES, PromptQualityScreens.MEASURE, PromptQualityScreens.VERSIONS,
                PromptQualityScreens.EVIDENCE);
        assertThat(PromptQualityScreens.MENUS).extracting(Menu::icon).containsExactly("fa-heartbeat",
                "fa-clipboard-check", "fa-balance-scale", "fa-code-branch", "fa-stamp");
        assertThat(PromptQualityScreens.MENUS).extracting(Menu::count)
                .containsExactly(null, Count.CASES, Count.MEASUREMENTS, Count.VERSIONS, Count.SEALED);
        assertThat(PromptQualityScreens.STATUS).isEqualTo("/contexa/admin/prompt-quality/status");
        assertThat(PromptQualityScreens.CASES).isEqualTo("/contexa/admin/prompt-quality/cases");
        assertThat(PromptQualityScreens.MEASURE).isEqualTo("/contexa/admin/prompt-quality/measure");
        // Quality plan 3.7: the two sealed prompt screens became the sealed evidence, under the group's addresses.
        assertThat(PromptQualityScreens.EVIDENCE).isEqualTo("/contexa/admin/prompt-quality/evidence");
    }

    @Test
    void theBarListsTheMenusWithTheirCountsInTheReadersLanguage() {
        EnumMap<Count, Long> counts = new EnumMap<>(Count.class);
        counts.put(Count.CASES, 76L);
        counts.put(Count.MEASUREMENTS, 12_345L);
        counts.put(Count.VERSIONS, 0L);
        counts.put(Count.SEALED, 1_248_000L);

        List<Tab> korean = new PromptQualityNav(PromptQualityScreens.MENUS, (count, scope) -> counts.get(count), null,
                Locale.KOREAN).tabs();
        List<Tab> english = new PromptQualityNav(PromptQualityScreens.MENUS, (count, scope) -> counts.get(count), null,
                Locale.ENGLISH).tabs();

        assertThat(korean).extracting(Tab::key).containsExactly("status", "cases", "measure", "versions", "evidence");
        assertThat(korean).extracting(Tab::count).containsExactly(null, 76L, 12_345L, 0L, 1_248_000L);
        assertThat(korean).extracting(Tab::shortCount).containsExactly(null, "76", "1.2만", "0", "124.8만");
        assertThat(english).extracting(Tab::shortCount).containsExactly(null, "76", "12.3K", "0", "1.2M");
        assertThat(english).extracting(Tab::fullCount).containsExactly(null, "76", "12,345", "0", "1,248,000");
        assertThat(english).extracting(Tab::countLabel).containsExactly(null, "pqa.nav.count.CASES",
                "pqa.nav.count.MEASUREMENTS", "pqa.nav.count.VERSIONS", "pqa.nav.count.SEALED");
        assertThat(english).extracting(Tab::label).containsExactly("pqa.nav.status", "pqa.nav.cases",
                "pqa.nav.measure", "pqa.nav.versions", "pqa.nav.evidence");
    }

    @Test
    void theCountsAreReadOnceAndOnlyWhenTheBarIsDrawnForTheScopeOfThePage() {
        AtomicInteger reads = new AtomicInteger();
        List<String> scopes = new ArrayList<>();
        PromptQualityNav nav = new PromptQualityNav(PromptQualityScreens.MENUS, (count, scope) -> {
            reads.incrementAndGet();
            scopes.add(scope);
            return 1L;
        }, "  tenant-a  ", Locale.ENGLISH);

        assertThat(reads).hasValue(0);
        assertThat(nav.scope()).isEqualTo("tenant-a");
        nav.tabs();
        nav.tabs();

        assertThat(reads).as("the menus with a count").hasValue(PromptQualityScreens.MENUS.size() - 1);
        assertThat(scopes).containsOnly("tenant-a");
        assertThat(new PromptQualityNav(PromptQualityScreens.MENUS, (count, scope) -> 1L, " ", null).scope()).isNull();
    }

    @Test
    void aMenuWithoutACountOrACountNotReadHasNoBadge() {
        List<Menu> menus = List.of(PromptQualityScreens.MENUS.get(0), PromptQualityScreens.MENUS.get(1));
        AtomicInteger reads = new AtomicInteger();

        List<Tab> tabs = new PromptQualityNav(menus, (count, scope) -> {
            reads.incrementAndGet();
            return null;
        }, null, Locale.KOREAN).tabs();

        assertThat(reads).hasValue(1);
        assertThat(tabs).extracting(Tab::key).containsExactly("status", "cases");
        assertThat(tabs).allSatisfy(tab -> {
            assertThat(tab.count()).isNull();
            assertThat(tab.shortCount()).isNull();
            assertThat(tab.fullCount()).isNull();
            assertThat(tab.countLabel()).isNull();
        });
    }

    @Test
    void everyWordOfTheBarAndTheMenusIsInBothLanguagesAndTranslated() throws IOException {
        Set<String> keys = new LinkedHashSet<>();
        PromptQualityScreens.MENUS.forEach(menu -> keys.add(menu.label()));
        Stream.of(Count.values()).forEach(count -> keys.add(count.label()));
        keys.addAll(List.of("pqa.nav.group", "pqa.nav.question.cases", "pqa.nav.question.measure", "menu.nav.pqa",
                "menu.pqa.status", "menu.pqa.cases", "menu.pqa.measure", "menu.pqa.versions", "menu.pqa.evidence"));

        Properties english = properties("contexa/i18n/messages.properties");
        Properties korean = properties("contexa/i18n/messages_ko.properties");

        assertThat(keys.stream().filter(key -> !english.containsKey(key)).toList()).as("in English").isEmpty();
        assertThat(keys.stream().filter(key -> !korean.containsKey(key)).toList()).as("in Korean").isEmpty();
        assertThat(keys.stream().filter(key -> english.getProperty(key).equals(korean.getProperty(key))).toList())
                .as("translated").isEmpty();
        assertThat(keys.stream().filter(key -> key.startsWith("pqa.nav.count."))
                .filter(key -> !english.getProperty(key).contains("{0}") || !korean.getProperty(key).contains("{0}"))
                .toList()).as("the count in its tooltip").isEmpty();
        // Quality plan 3.8: the name of the group, on two lines in the side menu.
        assertThat(korean.getProperty("menu.nav.pqa")).isEqualTo("프롬프트\n품질 보증");
        assertThat(english.getProperty("menu.nav.pqa")).isEqualTo("Prompt Quality\nAssurance");
        // The bar names its menus as the side menu does.
        assertThat(korean.getProperty("pqa.nav.cases")).isEqualTo(korean.getProperty("menu.pqa.cases"));
        assertThat(korean.getProperty("pqa.nav.measure")).isEqualTo(korean.getProperty("menu.pqa.measure"));
        assertThat(korean.getProperty("pqa.nav.versions")).isEqualTo(korean.getProperty("menu.pqa.versions"));
        assertThat(korean.getProperty("pqa.nav.status")).isEqualTo(korean.getProperty("menu.pqa.status"));
        assertThat(korean.getProperty("pqa.nav.evidence")).isEqualTo(korean.getProperty("menu.pqa.evidence"));
        assertThat(english.getProperty("pqa.nav.evidence")).isEqualTo(english.getProperty("menu.pqa.evidence"));
    }

    private static Properties properties(String resource) throws IOException {
        Properties properties = new Properties();
        try (InputStream input = PromptQualityNavTest.class.getClassLoader().getResourceAsStream(resource)) {
            assertThat(input).as(resource).isNotNull();
            properties.load(new InputStreamReader(input, StandardCharsets.UTF_8));
        }
        return properties;
    }
}
