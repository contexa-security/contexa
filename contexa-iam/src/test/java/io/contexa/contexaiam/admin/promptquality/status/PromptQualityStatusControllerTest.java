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
package io.contexa.contexaiam.admin.promptquality.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurementState;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.report.PromptQualityReportController;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityNav;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityNavAdvice;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityNavCounts;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityScreens;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleController;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.ControllerAdvice;

import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * Quality plan 3.6, 3.8: the state of quality opens for an administrator only, with the menu bar of the group, the
 * words of its script and where its buttons lead; its data is the state of quality of the scope, the operation read
 * for the scope's tenant (every tenant's for the platform's scope).
 */
class PromptQualityStatusControllerTest {

    private final Authentication admin = new TestingAuthenticationToken("admin", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
    private final Authentication user = new TestingAuthenticationToken("user", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_USER"));
    private final PromptQualityStatus status = mock(PromptQualityStatus.class);
    private final StaticMessageSource messages = new StaticMessageSource();
    private final MockMvc mvc;

    PromptQualityStatusControllerTest() {
        admin.setAuthenticated(true);
        user.setAuthenticated(true);
        messages.addMessage("pqa.status.todo.title", Locale.KOREAN, "확인이 필요한 것");
        messages.addMessage("pqa.status.todo.title", Locale.ENGLISH, "To check");
        messages.addMessage("pqa.report.ui.button", Locale.KOREAN, "품질 보고서 </script>");
        PromptQualityNavCounts counts = new PromptQualityNavCounts(() -> null, () -> null, () -> null, () -> null,
                () -> null, null);
        mvc = MockMvcBuilders.standaloneSetup(new PromptQualityStatusController(status, messages, new ObjectMapper()))
                .setControllerAdvice(new PromptQualityNavAdvice(counts)).build();
    }

    @Test
    void theScreenOpensForAnAdministratorWithTheBarTheWordsAndTheWaysOut() throws Exception {
        for (String address : List.of(PromptQualityScreens.STATUS, PromptQualityScreens.STATUS + "/")) {
            MvcResult result = mvc.perform(get(address).principal(admin).locale(Locale.KOREAN))
                    .andExpect(status().isOk())
                    .andExpect(view().name("contexa/admin/prompt-quality/status"))
                    .andExpect(model().attribute("screen", "status"))
                    .andExpect(model().attribute("activePage", "prompt-quality-status"))
                    .andExpect(model().attribute("apiBase", PromptQualityStatusController.API))
                    .andReturn();
            assertThat(result.getModelAndView().getModel().get(PromptQualityNavAdvice.ATTRIBUTE))
                    .isInstanceOf(PromptQualityNav.class);
            String words = (String) result.getModelAndView().getModel().get("scriptMessagesJson");
            assertThat(words).doesNotContain("</script>").contains("\"pqa.status.todo.title\":\"확인이 필요한 것\"");
            JsonNode paths = new ObjectMapper().readTree((String) result.getModelAndView().getModel().get("pathsJson"));
            assertThat(paths.path("measure").asText()).isEqualTo(PromptQualityScreens.MEASURE);
            assertThat(paths.path("cases").asText()).isEqualTo(PromptQualityScreens.CASES);
            assertThat(paths.path("versions").asText()).isEqualTo(PromptQualityScreens.VERSIONS);
            assertThat(paths.path("evidence").asText()).isEqualTo(PromptQualityScreens.EVIDENCE);
            assertThat(paths.path("review").asText()).isEqualTo("/contexa/admin/zero-trust/decisions?view=review");
            assertThat(paths.path("decisions").asText()).isEqualTo("/contexa/admin/zero-trust/decisions");
            assertThat(paths.path("report").asText()).isEqualTo(PromptQualityReportController.API);
        }
        MvcResult english = mvc.perform(get(PromptQualityScreens.STATUS).principal(admin).locale(Locale.ENGLISH))
                .andReturn();
        assertThat((String) english.getModelAndView().getModel().get("scriptMessagesJson"))
                .contains("\"pqa.status.todo.title\":\"To check\"");
    }

    @Test
    void theDataIsTheStateOfTheScopeWithTheOperationOfItsTenant() throws Exception {
        when(status.status(any(), any(), any())).thenReturn(new PromptQualityStatus.Status("tenant-a", "prompt",
                "v1.0", "DATABASE", QualityMeasurementState.BASELINE_PENDING, true, null, null, null, null,
                new PromptQualityCases.Counts(1, 0, 0, 2), 3, List.of(new PromptQualityStatus.ToCheck(
                "CASES_PENDING", "WARN", 2, Map.of()))));

        mvc.perform(get(PromptQualityStatusController.API).param("scope", "tenant-a").param("period", "month")
                        .principal(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value("v1.0"))
                .andExpect(jsonPath("$.state").value("BASELINE_PENDING"))
                .andExpect(jsonPath("$.measuring").value(true))
                .andExpect(jsonPath("$.cases.pending").value(2))
                .andExpect(jsonPath("$.pendingReviews").value(3))
                .andExpect(jsonPath("$.toCheck[0].kind").value("CASES_PENDING"));
        verify(status).status("tenant-a", "month", "tenant-a");

        mvc.perform(get(PromptQualityStatusController.API).param("scope", PromptVersionService.PLATFORM_SCOPE)
                .principal(admin)).andExpect(status().isOk());
        verify(status).status(PromptVersionService.PLATFORM_SCOPE, null, null);
        mvc.perform(get(PromptQualityStatusController.API).principal(admin)).andExpect(status().isOk());
        verify(status).status(isNull(), isNull(), isNull());
    }

    @Test
    void theScreenAndItsDataAreAnAdministratorsAlone() throws Exception {
        for (String address : List.of(PromptQualityScreens.STATUS, PromptQualityStatusController.API)) {
            mvc.perform(get(address).principal(user)).andExpect(status().isForbidden());
            mvc.perform(get(address)).andExpect(status().isForbidden());
        }
        verifyNoInteractions(status);
        assertThat(PromptQualityStatusController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo(PromptVersionConsoleController.class.getAnnotation(PreAuthorize.class).value());
        String[] packages = PromptQualityNavAdvice.class.getAnnotation(ControllerAdvice.class).basePackages();
        assertThat(PromptQualityStatusController.class.getPackageName()).startsWith(packages[0] + ".");
    }
}
