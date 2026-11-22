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
package io.contexa.contexaiam.admin.promptquality.screen;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Tab;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Quality plan 3.5, 3.8: the view of the wrong cases and their causes is the fourth view of measure and compare, opened
 * by its name on the latest measurement and on one, its script loaded with the screen's, its tab counting the wrong
 * answers of the page's measurement; its JSON is an administrator's, with the decisions rated inadequate unless asked
 * not to, and a change of a cause is refused with its code. Every word of the view is in both languages.
 */
class PromptQualityCauseApiControllerTest {

    private final Authentication admin = new TestingAuthenticationToken("admin-a", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
    private final Authentication user = new TestingAuthenticationToken("user", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_USER"));
    private final PromptQualityCauseScreen screen = mock(PromptQualityCauseScreen.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new PromptQualityCauseApiController(screen)).build();

    PromptQualityCauseApiControllerTest() {
        admin.setAuthenticated(true);
        user.setAuthenticated(true);
    }

    @Test
    void theCausesOfTheLatestMeasurementOrOfOneComeWithTheDecisionsUnlessAskedNot() throws Exception {
        PromptQualityCauseScreen.CausesView view = new PromptQualityCauseScreen.CausesView(41L, "v1.0", 1, "set-1", 1,
                Instant.parse("2026-11-22T10:00:00Z"), List.of(), 1, true, Instant.parse("2026-08-24T10:00:00Z"),
                Instant.parse("2026-11-22T10:00:00Z"), 0, 0, 90_000L,
                List.of(new PromptQualityCauseScreen.Tile("JUDGEMENT_ERROR", "PROMPT_VERSION", 1, 0, false)),
                List.of(new PromptQualityCauseScreen.Row(7L, "MEASUREMENT", "JUDGEMENT_ERROR", "JUDGEMENT_ERROR", false,
                        "S04", "GET /a (S04)", 1, List.of("ALLOW"), List.of("BLOCK"), null, null, List.of())));
        when(screen.causes(any(), any(), anyBoolean())).thenReturn(Optional.of(view));

        mvc.perform(get(PromptQualityCauseApiController.API + "/run/causes").param("scope", "tenant-a").principal(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.measureId").value(41))
                .andExpect(jsonPath("$.tiles[0].cause").value("JUDGEMENT_ERROR"))
                .andExpect(jsonPath("$.rows[0].given[0]").value("ALLOW"));
        verify(screen).causes("tenant-a", null, true);
        mvc.perform(get(PromptQualityCauseApiController.API + "/41/causes").param("decisions", "false")
                .principal(admin)).andExpect(status().isOk());
        verify(screen).causes(isNull(), eq(41L), eq(false));

        when(screen.causes(any(), eq(99L), anyBoolean())).thenReturn(Optional.empty());
        mvc.perform(get(PromptQualityCauseApiController.API + "/99/causes").principal(admin))
                .andExpect(status().isNotFound());
    }

    @Test
    void aChangeOfACauseIsKeptOrRefusedWithItsCode() throws Exception {
        when(screen.correct(any(), eq(7L), eq("UNSTABLE"), eq("admin-a"))).thenReturn(new PromptQualityCauseScreen.Row(
                7L, "MEASUREMENT", "UNSTABLE", "JUDGEMENT_ERROR", true, "S04", "S04", 1, List.of(), List.of(), null, null,
                List.of()));
        mvc.perform(post(PromptQualityCauseApiController.API + "/causes/7/category").principal(admin)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"category\":\"UNSTABLE\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.corrected").value(true));
        for (String[] refusal : List.of(new String[]{"DECISIONS_ONLY", "400"}, new String[]{"CATEGORY", "400"},
                new String[]{"NOT_FOUND", "404"}, new String[]{"UNAVAILABLE", "503"})) {
            when(screen.correct(any(), eq(8L), any(), any())).thenThrow(new PromptQualityCauseScreen.RefusedException(
                    refusal[0], "refused"));
            mvc.perform(post(PromptQualityCauseApiController.API + "/causes/8/category").principal(admin)
                            .contentType(MediaType.APPLICATION_JSON).content("{\"category\":\"INPUT_ERROR\"}"))
                    .andExpect(status().is(Integer.parseInt(refusal[1])))
                    .andExpect(jsonPath("$.code").value(refusal[0]));
        }
    }

    @Test
    void theCausesAreAnAdministratorsAlone() throws Exception {
        mvc.perform(get(PromptQualityCauseApiController.API + "/run/causes").principal(user))
                .andExpect(status().isForbidden());
        mvc.perform(post(PromptQualityCauseApiController.API + "/causes/7/category").principal(user)
                .contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
        verifyNoInteractions(screen);
    }

    /** The fourth view: its name opens it, its script comes with the screen's, its tab counts the wrong answers. */
    @Test
    void theViewIsTheFourthTabOfMeasureAndCompareWithItsCount() throws Exception {
        assertThat(PromptQualityMeasureScreen.VIEWS).extracting(PromptQualityMeasureViews.View::key)
                .containsExactly("runs", "run", "compare", "causes");
        assertThat(PromptQualityPageController.chosen("causes", "run")).isEqualTo("causes");
        ResourceBundleMessageSource messages = new ResourceBundleMessageSource();
        messages.setBasename("contexa/i18n/messages");
        messages.setDefaultEncoding("UTF-8");
        messages.setFallbackToSystemLocale(false);
        PromptQualityPageController counted = new PromptQualityPageController(messages, new ObjectMapper(),
                (view, scope, measureId) -> "causes".equals(view) ? (measureId != null ? 12L : 3L) : null);

        List<Tab> onRun = counted.tabs("causes", null, Locale.KOREAN, 41L);
        assertThat(onRun).extracting(Tab::text).containsExactly("측정 목록", "한 판의 결과", "두 판의 비교",
                "틀린 사례와 원인 12");
        assertThat(onRun).extracting(Tab::selected).containsExactly(false, false, false, true);
        assertThat(onRun.get(3).href()).isEqualTo("/contexa/admin/prompt-quality/measure/41?view=causes");
        assertThat(counted.tabs("runs", null, Locale.ENGLISH, null).get(3).text()).isEqualTo("Wrong cases and causes 3");
        PromptQualityPageController failing = new PromptQualityPageController(messages, new ObjectMapper(),
                (view, scope, measureId) -> {
                    throw new IllegalStateException("the database is away");
                });
        assertThat(failing.tabs("runs", null, Locale.ENGLISH, null).get(3).text()).isEqualTo("Wrong cases and causes");

        MockMvc pages = MockMvcBuilders.standaloneSetup(counted).build();
        MvcResult latest = pages.perform(get("/contexa/admin/prompt-quality/measure/run").param("view", "causes")
                .principal(admin)).andExpect(status().isOk()).andExpect(model().attribute("view", "causes")).andReturn();
        assertThat(String.valueOf(latest.getModelAndView().getModel().get("viewScripts")))
                .contains("/contexa/js/admin/prompt-quality/measure-causes.js?v=20261122-s3b");
        pages.perform(get("/contexa/admin/prompt-quality/measure/41").param("view", "causes").principal(admin))
                .andExpect(model().attribute("view", "causes")).andExpect(model().attribute("measureId", 41L));
    }

    @Test
    void everyWordOfTheViewIsInBothLanguages() throws IOException {
        Properties english = properties("contexa/i18n/messages.properties");
        Properties korean = properties("contexa/i18n/messages_ko.properties");
        Set<String> englishKeys = keys(english);

        assertThat(englishKeys).hasSizeGreaterThan(60).isEqualTo(keys(korean));
        assertThat(englishKeys).filteredOn(key -> english.getProperty(key).isBlank()).isEmpty();
        assertThat(englishKeys).filteredOn(key -> english.getProperty(key).equals(korean.getProperty(key))
                && english.getProperty(key).matches(".*[A-Za-z]{3,}.*")).isEmpty();
    }

    private static Set<String> keys(Properties bundle) {
        Set<String> keys = new TreeSet<>();
        bundle.stringPropertyNames().stream().filter(key -> key.startsWith("pqa.causes.")).forEach(keys::add);
        return keys;
    }

    private static Properties properties(String resource) throws IOException {
        Properties properties = new Properties();
        try (InputStream input = PromptQualityCauseApiControllerTest.class.getClassLoader()
                .getResourceAsStream(resource)) {
            assertThat(input).as(resource).isNotNull();
            properties.load(new InputStreamReader(input, StandardCharsets.UTF_8));
        }
        return properties;
    }
}
