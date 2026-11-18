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
package io.contexa.contexaiam.admin.web.zerotrust;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * K110: a console card title longer than a phone's title line has a short form, its key and ".short", which a phone
 * reads instead (ZT.title). A short form belongs to a title of its own language, is shorter and fills the same values.
 */
class ZeroTrustTitleShortFormsTest {

    private static final Pattern VALUE = Pattern.compile("\\{\\d+}");

    @Test
    @DisplayName("K110: every short card title is shorter than its title and fills the same values, in each language")
    void everyShortTitleIsAShorterFormOfItsTitle() throws IOException {
        int shortForms = 0;
        List<String> wrong = new ArrayList<>();
        for (String path : List.of("contexa/i18n/messages.properties", "contexa/i18n/messages_ko.properties")) {
            Properties bundle = bundle(path);
            for (String key : bundle.stringPropertyNames()) {
                if (!key.startsWith("zt.console.") || !key.endsWith(".short")) {
                    continue;
                }
                shortForms++;
                String title = bundle.getProperty(key.substring(0, key.length() - ".short".length()));
                String shortForm = bundle.getProperty(key);
                if (title == null || shortForm.isBlank() || shortForm.length() >= title.length()
                        || !values(shortForm).equals(values(title))) {
                    wrong.add(path + " " + key);
                }
            }
        }

        assertThat(wrong).isEmpty();
        assertThat(shortForms).isEqualTo(20);
    }

    @Test
    @DisplayName("K110: the SHADOW titles of the impact screen a phone cut have their short forms in Korean")
    void theShadowTitlesAPhoneCutHaveShortForms() throws IOException {
        Properties korean = bundle("contexa/i18n/messages_ko.properties");

        for (String card : List.of("funnel", "reasons", "burden")) {
            assertThat(korean.getProperty("zt.console.ui.impact." + card + ".title.shadow.short")).as(card)
                    .startsWith("적용 시 ");
        }
    }

    private static Set<String> values(String text) {
        Set<String> values = new TreeSet<>();
        Matcher matcher = VALUE.matcher(text);
        while (matcher.find()) {
            values.add(matcher.group());
        }
        return values;
    }

    private static Properties bundle(String path) throws IOException {
        Properties properties = new Properties();
        try (InputStream in = new ClassPathResource(path).getInputStream()) {
            properties.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
        return properties;
    }
}
