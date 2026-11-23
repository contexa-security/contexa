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
package io.contexa.contexaiam.admin.promptquality.report;

import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityNavAdvice;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleController;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.ControllerAdvice;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Quality plan 3.7, 5 step 8: the quality report is downloaded as its bundle by an administrator only, for the scope
 * and the whole UTC days asked for (the last day in the period), by the administrator who asked; a period the report
 * refuses is a bad request.
 */
class PromptQualityReportControllerTest {

    private final Authentication admin = new TestingAuthenticationToken("admin-a", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
    private final Authentication user = new TestingAuthenticationToken("user", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_USER"));
    private final PromptQualityReports reports = mock(PromptQualityReports.class);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new PromptQualityReportController(reports)).build();

    PromptQualityReportControllerTest() {
        admin.setAuthenticated(true);
        user.setAuthenticated(true);
    }

    @Test
    void theReportIsDownloadedAsItsBundleForTheDaysAndTheScopeAskedFor() throws Exception {
        byte[] zip = "PK-bundle".getBytes(StandardCharsets.UTF_8);
        when(reports.export(any())).thenReturn(new PromptQualityReports.Export(
                "prompt-quality-report-2026-11-22_120000.zip", zip, null));

        MvcResult result = mvc.perform(get(PromptQualityReportController.API).param("scope", "tenant-a")
                        .param("from", "2026-09-01").param("to", "2026-11-21").principal(admin))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/zip"))
                .andReturn();

        assertThat(result.getResponse().getHeader("Content-Disposition")).startsWith("attachment;")
                .contains("prompt-quality-report-2026-11-22_120000.zip");
        assertThat(result.getResponse().getContentAsByteArray()).isEqualTo(zip);
        ArgumentCaptor<PromptQualityReports.Request> asked = ArgumentCaptor.forClass(PromptQualityReports.Request.class);
        verify(reports).export(asked.capture());
        assertThat(asked.getValue()).isEqualTo(new PromptQualityReports.Request("tenant-a",
                Instant.parse("2026-09-01T00:00:00Z"), Instant.parse("2026-11-22T00:00:00Z"), "admin-a"));
    }

    @Test
    void withoutDaysTheReportTakesItsOwnPeriod() throws Exception {
        when(reports.export(any())).thenReturn(new PromptQualityReports.Export("report.zip", new byte[]{1}, null));

        mvc.perform(get(PromptQualityReportController.API).principal(admin)).andExpect(status().isOk());

        ArgumentCaptor<PromptQualityReports.Request> asked = ArgumentCaptor.forClass(PromptQualityReports.Request.class);
        verify(reports).export(asked.capture());
        assertThat(asked.getValue()).isEqualTo(new PromptQualityReports.Request(null, null, null, "admin-a"));
    }

    @Test
    void aPeriodTheReportRefusesIsABadRequest() throws Exception {
        when(reports.export(any())).thenThrow(new IllegalArgumentException("The period of the report ends before it"
                + " starts"));

        mvc.perform(get(PromptQualityReportController.API).param("from", "2026-11-21").param("to", "2026-11-01")
                .principal(admin)).andExpect(status().isBadRequest());
        mvc.perform(get(PromptQualityReportController.API).param("from", "not-a-day").principal(admin))
                .andExpect(status().isBadRequest());
        verify(reports, times(1)).export(any());
    }

    @Test
    void theReportIsAnAdministratorsAlone() throws Exception {
        mvc.perform(get(PromptQualityReportController.API).principal(user)).andExpect(status().isForbidden());
        mvc.perform(get(PromptQualityReportController.API)).andExpect(status().isForbidden());
        verifyNoInteractions(reports);
        assertThat(PromptQualityReportController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo(PromptVersionConsoleController.class.getAnnotation(PreAuthorize.class).value());
        String[] packages = PromptQualityNavAdvice.class.getAnnotation(ControllerAdvice.class).basePackages();
        assertThat(PromptQualityReportController.class.getPackageName()).startsWith(packages[0] + ".");
    }
}
