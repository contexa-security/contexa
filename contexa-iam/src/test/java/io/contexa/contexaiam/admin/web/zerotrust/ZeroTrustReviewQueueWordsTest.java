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
import java.util.List;
import java.util.Locale;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * K112: the review queue counted on the dashboard and on the console holds every decision waiting for review, whatever
 * its reason (ZeroTrustDecisionRecords.reviewPending). Every text that says what the queue holds names its three
 * reasons, in the words its rows show them by, in both languages.
 */
class ZeroTrustReviewQueueWordsTest {

    private static final List<String> REASONS = List.of("SAMPLE", "RULE_BREACH", "SHADOW_BLOCK");
    private static final List<String> QUEUE_WORDS = List.of("dashboard.ui.todo.reviewQueue.rule",
            "zt.console.ui.decisions.list.reviewAside", "zt.console.ui.trust.review.how",
            "zt.console.glossary.review.help");

    @Test
    @DisplayName("K112: the words of the review queue name its three reasons, in both languages")
    void theWordsOfTheReviewQueueNameItsThreeReasons() throws IOException {
        for (String path : List.of("contexa/i18n/messages.properties", "contexa/i18n/messages_ko.properties")) {
            Properties bundle = bundle(path);
            for (String key : QUEUE_WORDS) {
                String text = bundle.getProperty(key);
                assertThat(text).as(path + " " + key).isNotBlank();
                for (String reason : REASONS) {
                    String word = bundle.getProperty("zt.console.ui.decisions.review.reason." + reason);
                    assertThat(text.toLowerCase(Locale.ROOT)).as(path + " " + key + " " + reason)
                            .contains(word.toLowerCase(Locale.ROOT));
                }
            }
        }
    }

    @Test
    @DisplayName("K112: the dashboard's rule no longer says the queue holds the daily sample alone")
    void theDashboardsRuleIsNotTheSampleAlone() throws IOException {
        assertThat(bundle("contexa/i18n/messages_ko.properties").getProperty("dashboard.ui.todo.reviewQueue.rule"))
                .doesNotContain("하루 표본으로 뽑혀");
        assertThat(bundle("contexa/i18n/messages.properties").getProperty("dashboard.ui.todo.reviewQueue.rule"))
                .doesNotContain("sampled for the day");
    }

    private static Properties bundle(String path) throws IOException {
        Properties properties = new Properties();
        try (InputStream in = new ClassPathResource(path).getInputStream()) {
            properties.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
        return properties;
    }
}
