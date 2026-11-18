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

import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustDecisionOutcomes;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * K81, K84: the values of the decision list's outcome filter are every outcome kind, "no outcome yet" and "no
 * administrator's review"; the screen offers the same values, and each has its words in both languages, as each
 * outcome kind has its sentence.
 */
class ZeroTrustOutcomeFilterTest {

    private static final Pattern QUOTED = Pattern.compile("'([A-Z_]+)'");

    @Test
    void everyOutcomeKindIsAValueOfTheFilterAndTheScreen() throws IOException {
        Set<String> kinds = new LinkedHashSet<>();
        for (ZeroTrustDecisionOutcomes.Kind kind : ZeroTrustDecisionOutcomes.Kind.values()) {
            kinds.add(kind.name());
        }
        Set<String> expected = new LinkedHashSet<>(Set.of("NONE", ZeroTrustDecisionRecords.UNREVIEWED));
        expected.addAll(kinds);

        assertThat(ZeroTrustDecisionRecords.OUTCOMES).containsExactlyInAnyOrderElementsOf(expected);
        assertThat(screenValues()).containsExactlyInAnyOrderElementsOf(expected);
    }

    @Test
    void everyValueHasItsWordsInBothLanguages() throws IOException {
        Properties english = bundle("contexa/i18n/messages.properties");
        Properties korean = bundle("contexa/i18n/messages_ko.properties");

        for (String value : ZeroTrustDecisionRecords.OUTCOMES) {
            String key = "zt.console.ui.decisions.outcome." + value;
            assertThat(english.getProperty(key)).as(key + " [en]").isNotBlank();
            assertThat(korean.getProperty(key)).as(key + " [ko]").isNotBlank();
        }
        for (ZeroTrustDecisionOutcomes.Kind kind : ZeroTrustDecisionOutcomes.Kind.values()) {
            String key = "zt.console.outcome." + kind.name();
            assertThat(english.getProperty(key)).as(key + " [en]").isNotBlank();
            assertThat(korean.getProperty(key)).as(key + " [ko]").isNotBlank();
        }
        assertThat(korean.getProperty("zt.console.ui.decisions.outcome.UNREVIEWED")).isEqualTo("해제·유지·검토 없음");
        assertThat(korean.getProperty("zt.console.ui.decisions.outcome.CHALLENGE_CODE_REQUESTED")).isEqualTo("코드 요청");
    }

    /** The values the outcome filter of the decision list offers: its list of outcomes and the two before it. */
    private static Set<String> screenValues() throws IOException {
        String script = new ClassPathResource("static/contexa/js/admin/zero-trust/decisions.js")
                .getContentAsString(StandardCharsets.UTF_8);
        Matcher outcomes = Pattern.compile("const OUTCOMES = \\[([^\\]]*)]").matcher(script);
        Matcher filter = Pattern.compile("key: 'outcome', values: \\[([^\\]]*)]\\.concat\\(OUTCOMES\\)").matcher(script);
        assertThat(outcomes.find()).isTrue();
        assertThat(filter.find()).isTrue();
        Set<String> values = new LinkedHashSet<>();
        for (String list : new String[] {filter.group(1), outcomes.group(1)}) {
            Matcher value = QUOTED.matcher(list);
            while (value.find()) {
                values.add(value.group(1));
            }
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
