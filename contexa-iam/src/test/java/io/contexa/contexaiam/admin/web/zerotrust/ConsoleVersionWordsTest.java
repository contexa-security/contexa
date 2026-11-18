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

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * K55: the screens name a prompt's version by the word the version screens use (plan 3.2: "버전", "version"), the
 * Zero Trust console and the prompt inspection included: no value they show says bundle (번들, 묶음, bundle). The keys
 * keep their names; "묶음" stays where it means a group of reasons, a batch or a set of policies.
 */
class ConsoleVersionWordsTest {

    /** The values of "묶음" that do not mean a prompt's version. */
    private static final Set<String> OTHER_GROUPS = Set.of("zt.console.ui.overview.reasons.aside",
            "zt.console.ui.overview.reasons.aside.shadow", "zt.console.ui.overview.noDecisionReason.BATCH_REQUEUE_EXHAUSTED",
            "zt.console.ui.operations.noDecisionReason.BATCH_REQUEUE_EXHAUSTED");
    private static final List<String> SCREENS = List.of("zt.console.", "promptInspection.");

    @Test
    void noValueTheConsoleShowsSaysBundle() throws IOException {
        Properties english = bundle("contexa/i18n/messages.properties");
        Properties korean = bundle("contexa/i18n/messages_ko.properties");
        int checked = 0;
        for (Properties messages : List.of(english, korean)) {
            for (String key : messages.stringPropertyNames()) {
                if (SCREENS.stream().noneMatch(key::startsWith)) {
                    continue;
                }
                checked++;
                String value = messages.getProperty(key);
                assertThat(value).as(key).doesNotContainIgnoringCase("bundle").doesNotContain("번들");
                if (!OTHER_GROUPS.contains(key)) {
                    assertThat(value).as(key).doesNotContain("묶음");
                }
            }
        }
        assertThat(checked).isGreaterThan(1000);
        assertThat(korean.getProperty("promptInspection.replay.title")).isEqualTo("버전으로 재생");
        assertThat(korean.getProperty("promptInspection.replay.bundle")).isEqualTo("버전");
        assertThat(korean.getProperty("promptInspection.detail.reason.earlierBundle")).startsWith("옛 버전,");
        assertThat(english.getProperty("promptInspection.replay.title")).isEqualTo("Replay with a version");
        assertThat(korean.getProperty("zt.console.ui.operations.usage.title")).isEqualTo("버전·모델 사용");
        assertThat(english.getProperty("zt.console.ui.operations.usage.bundleModel")).isEqualTo("Version · model");
        assertThat(korean.getProperty("zt.console.ui.band.bundle")).isEqualTo("버전 {0}");
    }

    private static Properties bundle(String path) throws IOException {
        Properties properties = new Properties();
        try (InputStream in = new ClassPathResource(path).getInputStream()) {
            properties.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
        return properties;
    }
}
