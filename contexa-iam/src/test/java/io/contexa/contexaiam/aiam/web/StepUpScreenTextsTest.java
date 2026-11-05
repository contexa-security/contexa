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
package io.contexa.contexaiam.aiam.web;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.support.PropertiesLoaderUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The step-up answers a wrong code and a code past its limit alike, so the screen cannot tell them apart either: what it
 * says after a refused code has to serve both, and a user whose code is used up has to read that a new one is the way on.
 */
class StepUpScreenTextsTest {

    private static final String KEY = "zerotrust.stepup.code.failed";

    private static String template() throws IOException {
        return new ClassPathResource("templates/contexa/zero-trust/step-up.html")
                .getContentAsString(StandardCharsets.UTF_8);
    }

    private static Properties messages(String file) throws IOException {
        return PropertiesLoaderUtils.loadProperties(new ClassPathResource("contexa/i18n/" + file));
    }

    @Test
    @DisplayName("a refused code tells the user to ask for a new one, in every language")
    void aRefusedCodeTellsTheUserToAskForANewOne() throws IOException {
        assertThat(messages("messages.properties").getProperty(KEY)).contains("new code");
        assertThat(messages("messages_ko.properties").getProperty(KEY)).contains("새 코드");
    }

    @Test
    @DisplayName("the screen shows that text after a refused code, and keeps its own for a passkey")
    void theScreenShowsItAfterARefusedCode() throws IOException {
        String template = template();

        assertThat(template).contains("data-code-failed=#{" + KEY + "}");
        assertThat(template).containsPattern("post\\('/code/verify'[^;]*texts\\.codeFailed\\)");
        assertThat(template).doesNotContainPattern("post\\('/passkey/verify'[^;]*texts\\.codeFailed");
    }
}
