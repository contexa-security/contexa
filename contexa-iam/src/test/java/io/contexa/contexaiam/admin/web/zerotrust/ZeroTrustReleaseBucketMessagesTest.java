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
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The user's choice (2026-11-17): the release median reads as its bucket. Every bucket of the hourly table has its
 * words in both languages, and the definition names the buckets and what is counted.
 */
class ZeroTrustReleaseBucketMessagesTest {

    @Test
    void everyReleaseBucketHasItsWordsInBothLanguages() throws IOException {
        Properties english = bundle("contexa/i18n/messages.properties");
        Properties korean = bundle("contexa/i18n/messages_ko.properties");
        int buckets = ZeroTrustConsoleReader.RELEASE_BOUNDS_MINUTES.length + 1;

        for (int i = 0; i < buckets; i++) {
            String key = "zt.console.ui.releaseBucket." + i;
            assertThat(english.getProperty(key)).as(key + " [en]").isNotBlank();
            assertThat(korean.getProperty(key)).as(key + " [ko]").isNotBlank();
        }
        assertThat(english).doesNotContainKey("zt.console.ui.releaseBucket." + buckets);
        assertThat(korean.getProperty("zt.console.ui.releaseBucket.3")).isEqualTo("1~2시간 사이");
        assertThat(korean.getProperty("zt.console.ui.releaseBucket." + (buckets - 1))).isEqualTo("7일 넘음");
        assertThat(korean.getProperty("zt.console.metric.releaseMedian.description"))
                .contains("15분·30분·1·2·4·8·24·72시간·7일").contains("기간에 내린 차단 가운데 해제된 것");
        assertThat(english.getProperty("zt.console.metric.releaseMedian.description")).contains("bucket");
        assertThat(english).doesNotContainKey("zt.console.metric.releaseMedianHours.label");
        assertThat(korean).doesNotContainKey("zt.console.metric.releaseMedianHours.label");
    }

    private static Properties bundle(String path) throws IOException {
        Properties properties = new Properties();
        try (InputStream in = new ClassPathResource(path).getInputStream()) {
            properties.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
        return properties;
    }
}
