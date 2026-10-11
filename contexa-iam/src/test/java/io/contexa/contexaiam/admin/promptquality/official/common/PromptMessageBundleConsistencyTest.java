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
package io.contexa.contexaiam.admin.promptquality.official.common;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W1-16: the core's verification bundle copies the IAM messages it shares word for word, so the core alone and an
 * application with the IAM module show the same text.
 */
class PromptMessageBundleConsistencyTest {

    @ParameterizedTest
    @ValueSource(strings = {"", "_ko"})
    void theCoreBundleCopiesTheSharedIamMessagesWordForWord(String languageSuffix) throws IOException {
        Properties core = load("i18n/core-verification-messages" + languageSuffix + ".properties");
        Properties iam = load("i18n/messages" + languageSuffix + ".properties");

        assertThat(core).isNotEmpty();
        for (String key : core.stringPropertyNames()) {
            assertThat(iam.getProperty(key)).as(key).isEqualTo(core.getProperty(key));
        }
    }

    private Properties load(String resource) throws IOException {
        InputStream stream = getClass().getClassLoader().getResourceAsStream(resource);
        assertThat(stream).as(resource).isNotNull();
        Properties properties = new Properties();
        try (Reader reader = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        return properties;
    }
}
