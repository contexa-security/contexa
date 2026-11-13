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

import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.MediaType;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

class SeedTextResponseAdviceTest {

    private static final String GROUP_KO = "개발본부";

    private final SeedTextResponseAdvice advice = new SeedTextResponseAdvice(new SeedTexts(Map.of(
            "group.development.name", Map.of("ko", GROUP_KO, "en", "Development division"))), new ObjectMapper());

    @AfterEach
    void resetLocale() {
        LocaleContextHolder.resetLocaleContext();
    }

    @Test
    @DisplayName("D31: a list read by a page script shows the seed texts in the language of the page")
    void aListReadByAPageScriptShowsTheSeedTextsInThePageLanguage() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        Map<String, Object> group = Map.of("id", 2, "name", GROUP_KO, "tags", List.of(GROUP_KO, "other"));
        Object body = Map.of("content", List.of(group));

        Object written = write(body, "GET");

        assertThat(written).isInstanceOf(JsonNode.class);
        JsonNode first = ((JsonNode) written).get("content").get(0);
        assertThat(first.get("name").asText()).isEqualTo("Development division");
        assertThat(first.get("tags").get(0).asText()).isEqualTo("Development division");
        assertThat(first.get("tags").get(1).asText()).isEqualTo("other");
        assertThat(first.get("id").asInt()).isEqualTo(2);
        // the object the answer was made from is not changed
        assertThat(group.get("name")).isEqualTo(GROUP_KO);
    }

    @Test
    @DisplayName("D31: an answer without a seed text, and the answer of a write, are written as they are")
    void otherAnswersAreWrittenAsTheyAre() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        Object plain = Map.of("name", "A group an administrator named");
        Object saved = Map.of("name", GROUP_KO);

        assertThat(write(plain, "GET")).isSameAs(plain);
        assertThat(write(saved, "POST")).isSameAs(saved);
        assertThat(advice.supports(null, StringHttpMessageConverter.class)).isFalse();
        assertThat(advice.supports(null, MappingJackson2HttpMessageConverter.class)).isTrue();
    }

    private Object write(Object body, String method) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, "/contexa/admin/access-center/api/groups");
        return advice.beforeBodyWrite(body, null, MediaType.APPLICATION_JSON, MappingJackson2HttpMessageConverter.class,
                new ServletServerHttpRequest(request), new ServletServerHttpResponse(new MockHttpServletResponse()));
    }
}
