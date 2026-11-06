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
package io.contexa.contexaiam.admin.web;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every message a console template names by its key is in the English and the Korean bundle, so no screen shows a
 * key such as {@code ??common.action.cancel_en??} in place of its text. Keys built at run time are not checked.
 */
class ConsoleMessageKeysTest {

    private static final Pattern MESSAGE_EXPRESSION = Pattern.compile("#\\{([A-Za-z0-9_.-]+)\\s*[(}]");
    private static final Pattern MESSAGE_CALL = Pattern.compile("#messages\\.msg\\(\\s*'([A-Za-z0-9_.-]+)'");

    @Test
    @DisplayName("every key a console template names is in both bundles")
    void everyKeyATemplateNamesIsInBothBundles() throws IOException {
        Properties english = bundle("contexa/i18n/messages.properties");
        Properties korean = bundle("contexa/i18n/messages_ko.properties");
        Resource[] templates = new PathMatchingResourcePatternResolver().getResources("classpath*:templates/contexa/**/*.html");
        assertThat(templates).hasSizeGreaterThan(50);

        List<String> missing = new ArrayList<>();
        for (Resource template : templates) {
            String[] lines = template.getContentAsString(StandardCharsets.UTF_8).split("\\R", -1);
            for (int i = 0; i < lines.length; i++) {
                for (Pattern pattern : List.of(MESSAGE_EXPRESSION, MESSAGE_CALL)) {
                    Matcher matcher = pattern.matcher(lines[i]);
                    while (matcher.find()) {
                        String key = matcher.group(1);
                        if (!english.containsKey(key) || !korean.containsKey(key)) {
                            missing.add(template.getFilename() + ":" + (i + 1) + " " + key
                                    + (english.containsKey(key) ? "" : " [en]") + (korean.containsKey(key) ? "" : " [ko]"));
                        }
                    }
                }
            }
        }

        assertThat(missing).isEmpty();
    }

    private static Properties bundle(String path) throws IOException {
        Properties properties = new Properties();
        try (InputStream in = new ClassPathResource(path).getInputStream()) {
            properties.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
        assertThat(properties).hasSizeGreaterThan(1000);
        return properties;
    }
}
