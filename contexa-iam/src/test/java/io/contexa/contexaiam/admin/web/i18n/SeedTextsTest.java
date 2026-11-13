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
package io.contexa.contexaiam.admin.web.i18n;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import static org.assertj.core.api.Assertions.assertThat;

class SeedTextsTest {

    private static final String GROUP_KO = "개발본부";

    private final SeedTexts texts = new SeedTexts(Map.of(
            "group.development.name", Map.of("ko", GROUP_KO, "en", "Development division"),
            "policy.automatic.description", Map.of("ko", "역할 '{0}' 의 자동 동기화 정책",
                    "en", "Auto-synchronized policy for role '{0}'"),
            "only.korean", Map.of("ko", "한국어만")));

    @Test
    @DisplayName("D31: a seed text is shown in the language of the page, whichever language it was stored in")
    void aSeedTextIsShownInTheLanguageOfThePage() {
        assertThat(texts.translate(GROUP_KO, Locale.ENGLISH)).isEqualTo("Development division");
        assertThat(texts.translate("Development division", Locale.KOREAN)).isEqualTo(GROUP_KO);
        assertThat(texts.translate(GROUP_KO, Locale.KOREA)).isEqualTo(GROUP_KO);
    }

    @Test
    @DisplayName("D31: a text that is no seed text, or a seed text without the page's language, stays as it is")
    void otherTextsStayAsTheyAre() {
        assertThat(texts.translate("A group an administrator named", Locale.ENGLISH))
                .isEqualTo("A group an administrator named");
        assertThat(texts.translate(GROUP_KO + " ", Locale.ENGLISH)).isEqualTo(GROUP_KO + " ");
        assertThat(texts.translate("한국어만", Locale.ENGLISH)).isEqualTo("한국어만");
        assertThat(texts.translate(GROUP_KO, Locale.JAPANESE)).isEqualTo(GROUP_KO);
        assertThat(texts.translate(null, Locale.ENGLISH)).isNull();
    }

    @Test
    @DisplayName("D31: a generated text keeps the value it names")
    void aGeneratedTextKeepsTheValueItNames() {
        assertThat(texts.translate("Auto-synchronized policy for role 'ROLE_USER'", Locale.KOREAN))
                .isEqualTo("역할 'ROLE_USER' 의 자동 동기화 정책");
        assertThat(texts.translate("Auto-synchronized policy for role 'ROLE_USER'", Locale.ENGLISH))
                .isEqualTo("Auto-synchronized policy for role 'ROLE_USER'");
    }

    @Test
    @DisplayName("D31: a label that names a seed text and what it belongs to is translated in its seed part")
    void aLabelWithTheNameOfWhatItBelongsToIsTranslated() {
        assertThat(texts.translate(GROUP_KO + " (ROLE_DEVELOPER)", Locale.ENGLISH))
                .isEqualTo("Development division (ROLE_DEVELOPER)");
        assertThat(texts.translate("A group an administrator named (ROLE_X)", Locale.ENGLISH))
                .isEqualTo("A group an administrator named (ROLE_X)");
    }

    @Test
    @DisplayName("D31: the seed texts of the module are read from the class path, each in Korean and English")
    void theSeedTextsOfTheModuleAreRead() throws IOException {
        SeedTexts loaded = SeedTexts.load(new PathMatchingResourcePatternResolver());

        assertThat(loaded.isEmpty()).isFalse();
        assertThat(loaded.translate("일반 사용자 역할", Locale.ENGLISH)).isEqualTo("Regular user");
        assertThat(loaded.translate("Regular user", Locale.KOREAN)).isEqualTo("일반 사용자 역할");

        Set<String> korean = new HashSet<>();
        Set<String> english = new HashSet<>();
        Pattern line = Pattern.compile("^([a-z0-9.-]+)\\.(ko|en)=", Pattern.MULTILINE);
        try (InputStream in = getClass().getResourceAsStream("/META-INF/contexa/seed-texts.properties")) {
            Matcher matcher = line.matcher(new String(in.readAllBytes(), StandardCharsets.ISO_8859_1));
            while (matcher.find()) {
                (matcher.group(2).equals("ko") ? korean : english).add(matcher.group(1));
            }
        }
        assertThat(korean).isNotEmpty().isEqualTo(english);
    }

    @Test
    @DisplayName("D31: every Korean text of the IAM seed SQL is a seed text")
    void everyKoreanTextOfTheSeedSqlIsASeedText() throws IOException {
        SeedTexts loaded = SeedTexts.load(new PathMatchingResourcePatternResolver());
        String sql;
        try (InputStream in = getClass().getResourceAsStream("/META-INF/contexa/db/data.sql")) {
            sql = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        Matcher literal = Pattern.compile("'((?:[^']|'')*)'").matcher(sql.replaceAll("(?m)^\\s*--.*$", ""));
        Set<String> untranslated = new HashSet<>();
        while (literal.find()) {
            String text = literal.group(1).replace("''", "'");
            if (text.codePoints().anyMatch(c -> c >= 0xAC00 && c <= 0xD7A3)
                    && loaded.translate(text, Locale.ENGLISH).equals(text)) {
                untranslated.add(text);
            }
        }
        assertThat(untranslated).isEmpty();
    }
}
