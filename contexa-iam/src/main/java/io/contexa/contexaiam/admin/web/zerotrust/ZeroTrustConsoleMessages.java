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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

/**
 * The console's words for its screens: every message whose key starts with {@value #PREFIX}, in the language of the
 * request, as one JSON object the screens read. The keys are read from the default messages, so a new message needs
 * no list of its own; the placeholders stay for the screen to fill.
 */
@Slf4j
final class ZeroTrustConsoleMessages {

    static final String PREFIX = "zt.console.";
    private static final String DEFAULT_MESSAGES = "contexa/i18n/messages.properties";
    private static volatile List<String> keys;

    private ZeroTrustConsoleMessages() {
    }

    static List<String> keys() {
        List<String> known = keys;
        if (known != null) {
            return known;
        }
        Properties properties = new Properties();
        try (InputStream in = new ClassPathResource(DEFAULT_MESSAGES).getInputStream()) {
            properties.load(in);
        } catch (IOException unreadable) {
            log.error("[ZeroTrustConsole] The console's messages could not be read from {}", DEFAULT_MESSAGES,
                    unreadable);
            return List.of();
        }
        known = properties.stringPropertyNames().stream().filter(key -> key.startsWith(PREFIX)).sorted().toList();
        keys = known;
        return known;
    }

    /** The console's messages in the locale, as JSON safe to put inside a script element. */
    static String json(MessageSource messages, Locale locale, ObjectMapper objectMapper) {
        Map<String, String> resolved = new LinkedHashMap<>();
        Locale language = locale != null ? locale : Locale.ENGLISH;
        for (String key : keys()) {
            resolved.put(key, messages != null ? messages.getMessage(key, null, key, language) : key);
        }
        try {
            return objectMapper.writeValueAsString(resolved).replace("</", "<\\/");
        } catch (JsonProcessingException unwritable) {
            log.error("[ZeroTrustConsole] The console's messages could not be written", unwritable);
            return "{}";
        }
    }
}
