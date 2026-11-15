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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.DecisionPage;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.DecisionRow;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.EvaluationSaved;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/** Console plan stage 3: the console's addresses, its administrators only, and the shapes of its answers. */
class ZeroTrustConsoleControllerTest {

    private final ZeroTrustDecisionRecords records = mock(ZeroTrustDecisionRecords.class);
    private final ZeroTrustConsoleService service = new ZeroTrustConsoleService(() -> null, null, null, null, () -> null,
            false, Clock.fixed(Instant.parse("2026-11-15T10:30:00Z"), ZoneOffset.UTC));
    private final Authentication admin = new UsernamePasswordAuthenticationToken("admin", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
    private final Authentication user = new UsernamePasswordAuthenticationToken("alice", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_USER"));
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.standaloneSetup(new ZeroTrustConsoleController(service, records, null,
                new ObjectMapper())).build();
    }

    @Test
    void theSevenScreensAreTheConsolesTemplates() throws Exception {
        for (String[] screen : new String[][] {{"", "overview"}, {"/impact", "impact"}, {"/trust", "trust"},
                {"/decisions", "decisions"}, {"/decisions/obs-1", "decision"}, {"/adoption", "adoption"},
                {"/operations", "operations"}}) {
            mvc.perform(get("/contexa/admin/zero-trust" + screen[0]).principal(admin))
                    .andExpect(status().isOk())
                    .andExpect(view().name("contexa/admin/zero-trust/" + screen[1]));
        }
    }

    /** A decision's detail lights the decision records' menu (data-menu.sql has no menu of its own for it). */
    @Test
    void aDecisionsDetailBelongsToTheDecisionRecordsMenu() throws Exception {
        mvc.perform(get("/contexa/admin/zero-trust/decisions/obs-1").principal(admin))
                .andExpect(model().attribute("activePage", "zero-trust-decisions"));
        mvc.perform(get("/contexa/admin/zero-trust/trust").principal(admin))
                .andExpect(model().attribute("activePage", "zero-trust-trust"));
    }

    /** Console plan 5-4·5-5: a request opens its decision, else the records searched for it. */
    @Test
    void aRequestOpensItsDecisionOrTheSearchForIt() throws Exception {
        when(records.observationOfRequest("request-1")).thenReturn("obs 1");
        mvc.perform(get("/contexa/admin/zero-trust/decisions/request/request-1").principal(admin))
                .andExpect(redirectedUrl("/contexa/admin/zero-trust/decisions/obs%201"));
        mvc.perform(get("/contexa/admin/zero-trust/decisions/request/request-2").principal(admin))
                .andExpect(redirectedUrl("/contexa/admin/zero-trust/decisions?q=request-2"));
        mvc.perform(get("/contexa/admin/zero-trust/decisions/request/request-1").principal(user))
                .andExpect(status().isForbidden());
    }

    @Test
    void onlyAnAdministratorReadsTheConsole() throws Exception {
        mvc.perform(get("/contexa/admin/api/zero-trust/overview").principal(user)).andExpect(status().isForbidden());
        mvc.perform(get("/contexa/admin/zero-trust/trust").principal(user)).andExpect(status().isForbidden());
        mvc.perform(post("/contexa/admin/api/zero-trust/decisions/obs-1/evaluation").principal(user)
                .contentType("application/json").content("{\"valid\":true}")).andExpect(status().isForbidden());
        verify(records, never()).evaluate(anyString(), any(), anyString());
    }

    /** Without a database every number says why it has none: no 0 is shown for nothing. */
    @Test
    void anOverviewWithoutDataSaysWhy() throws Exception {
        mvc.perform(get("/contexa/admin/api/zero-trust/overview").param("period", "day").principal(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.header.period.key").value("day"))
                .andExpect(jsonPath("$.stopped.stopped.value").doesNotExist())
                .andExpect(jsonPath("$.stopped.stopped.noDataReason").value(ZeroTrustConsoleMetrics.NO_DECISIONS));
    }

    /** Console plan 5-2 ⑥: a screen's numbers as a CSV, each metric with the reason it has none. */
    @Test
    void aScreensNumbersComeAsACsv() throws Exception {
        String csv = mvc.perform(get("/contexa/admin/api/zero-trust/overview.csv").param("period", "day").principal(admin))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"zero-trust-overview.csv\""))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(csv).startsWith("﻿" + ZeroTrustConsoleCsv.HEADER);
        assertThat(csv).contains("stopped.stopped,").contains("," + ZeroTrustConsoleMetrics.NO_DECISIONS);
        for (String screen : List.of("impact", "trust", "adoption", "operations")) {
            mvc.perform(get("/contexa/admin/api/zero-trust/" + screen + ".csv").principal(admin))
                    .andExpect(status().isOk());
        }
        mvc.perform(get("/contexa/admin/api/zero-trust/other.csv").principal(admin)).andExpect(status().isNotFound());
        mvc.perform(get("/contexa/admin/api/zero-trust/trust.csv").principal(user)).andExpect(status().isForbidden());
    }

    /** Console plan 5-2 ③: the slowest-first order reads the slowest decisions, one page. */
    @Test
    void theSlowestOrderReadsTheSlowestDecisions() throws Exception {
        when(records.slowest(any(), isNull(), any())).thenReturn(new DecisionPage(List.of(), null));
        mvc.perform(get("/contexa/admin/api/zero-trust/decisions").param("order", "slowest").principal(admin))
                .andExpect(status().isOk());
        verify(records).slowest(any(), isNull(), any());
        verify(records, never()).list(any(), any(), any(), any());
    }

    @Test
    void aPeriodThatCannotBeReadIsABadRequest() throws Exception {
        mvc.perform(get("/contexa/admin/api/zero-trust/overview").param("period", "custom").param("from", "soon")
                .principal(admin)).andExpect(status().isBadRequest());
    }

    @Test
    void theListPassesItsFiltersAndCursor() throws Exception {
        when(records.list(any(), isNull(), any(), eq("cursor-1"))).thenReturn(new DecisionPage(List.of(), "cursor-2"));

        mvc.perform(get("/contexa/admin/api/zero-trust/decisions").param("cursor", "cursor-1").param("action", "BLOCK")
                        .principal(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.nextCursor").value("cursor-2"));
    }

    @Test
    void anEvaluationIsSavedAndAnInvalidOneIsABadRequest() throws Exception {
        when(records.evaluate(eq("obs-1"), any(), eq("admin")))
                .thenReturn(new EvaluationSaved("outcome-1", "obs-1", "EVALUATED_VALID"));
        when(records.evaluate(eq("obs-2"), any(), eq("admin"))).thenThrow(new IllegalArgumentException("no verdict"));

        mvc.perform(post("/contexa/admin/api/zero-trust/decisions/obs-1/evaluation").principal(admin)
                        .contentType("application/json").content("{\"valid\":true}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.kind").value("EVALUATED_VALID"));
        mvc.perform(post("/contexa/admin/api/zero-trust/decisions/obs-2/evaluation").principal(admin)
                        .contentType("application/json").content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_EVALUATION"));
        mvc.perform(post("/contexa/admin/api/zero-trust/decisions/obs-3/evaluation").principal(admin)
                .contentType("application/json").content("{\"valid\":true}")).andExpect(status().isNotFound());
    }

    @Test
    void theCsvDefusesFormulasAndQuotesSeparators() throws Exception {
        when(records.export(any(), isNull(), any())).thenReturn(List.of(new DecisionRow("obs-1", "2026-11-15T10:00:00Z",
                "=cmd()", "/api/a,b", "GET", "SENSITIVE", "BLOCK", "MODEL", "H2", "DEVIATION_DEVICE", "DEVIATION", null,
                1500L, "ENFORCE", "HUMAN")));

        String csv = mvc.perform(get("/contexa/admin/api/zero-trust/decisions.csv").principal(admin))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/csv"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        assertThat(csv).contains("'=cmd()").contains("\"/api/a,b\"").doesNotContain(",=cmd()");
        assertThat(ZeroTrustConsoleController.cell("@SUM(A1)")).isEqualTo("'@SUM(A1)");
        assertThat(ZeroTrustConsoleController.cell(null)).isEmpty();
    }
}
