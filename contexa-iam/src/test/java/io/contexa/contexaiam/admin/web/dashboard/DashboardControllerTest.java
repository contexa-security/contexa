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
package io.contexa.contexaiam.admin.web.dashboard;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.AgentsPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.AttentionPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.AttentionRow;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.BlockedPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.ChangeRow;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.ChangesPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.Count;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.DashboardView;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.DayCount;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.DenialsPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.IamPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.OperationsPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.PolicyPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.SecurityPart;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.Signal;
import io.contexa.contexaiam.admin.web.dashboard.DashboardDtos.SystemPart;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Period;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/** Plan step 9 (N1): the dashboard's page and JSON, an administrator's only, with the period it is asked for. */
class DashboardControllerTest {

    private final DashboardService service = mock(DashboardService.class);
    private final Authentication admin = new UsernamePasswordAuthenticationToken("admin", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
    private final Authentication user = new UsernamePasswordAuthenticationToken("alice", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_USER"));
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        StaticMessageSource messages = new StaticMessageSource();
        messages.addMessage("dashboard.ui.title", Locale.ENGLISH, "Dashboard");
        messages.addMessage("zt.console.ui.period.week", Locale.ENGLISH, "7 days");
        mvc = MockMvcBuilders.standaloneSetup(new DashboardController(service, messages, new ObjectMapper())).build();
    }

    @Test
    void thePageIsTheDashboardsTemplateWithTheWordsOfItsScript() throws Exception {
        for (String address : List.of("/contexa/admin", "/contexa/admin/", "/contexa/admin/dashboard")) {
            mvc.perform(get(address).principal(admin))
                    .andExpect(status().isOk())
                    .andExpect(view().name("contexa/admin/dashboard"))
                    .andExpect(model().attribute("activePage", "dashboard"))
                    .andExpect(model().attribute("apiBase", "/contexa/admin/api/dashboard"));
        }
        String words = (String) mvc.perform(get("/contexa/admin/dashboard").principal(admin)).andReturn()
                .getModelAndView().getModel().get("scriptMessagesJson");
        assertThat(words).contains("\"dashboard.ui.title\"").contains("\"zt.console.ui.period.week\"")
                .contains("admin.system.settings.combining.algorithm.first_applicable");
    }

    @Test
    void onlyAnAdministratorOpensThePageOrItsNumbers() throws Exception {
        mvc.perform(get("/contexa/admin/dashboard").principal(user)).andExpect(status().isForbidden());
        mvc.perform(get("/contexa/admin/api/dashboard").principal(user)).andExpect(status().isForbidden());
        mvc.perform(get("/contexa/admin/api/dashboard")).andExpect(status().isForbidden());
        verify(service, never()).dashboard(any(), any());
        PreAuthorize rule = DashboardController.class.getAnnotation(PreAuthorize.class);
        assertThat(rule).isNotNull();
        assertThat(rule.value()).isEqualTo("hasAuthority('ROLE_ADMIN')");
    }

    @Test
    void theNumbersAreThePeriodsAndHaveTheShapeTheScriptReads() throws Exception {
        when(service.dashboard(eq("month"), any())).thenReturn(answer("month"));
        mvc.perform(get("/contexa/admin/api/dashboard").param("period", "month").principal(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.period.key").value("month"))
                .andExpect(jsonPath("$.iam.admins").value(4))
                .andExpect(jsonPath("$.iam.adminsWithoutMfa").value(2))
                .andExpect(jsonPath("$.iam.activeHierarchies").value(true))
                .andExpect(jsonPath("$.policy.changesByDay[0].day").value("2026-11-11"))
                .andExpect(jsonPath("$.policy.conflictCount").value(1))
                .andExpect(jsonPath("$.security.failuresByDay[0].count").value(176))
                .andExpect(jsonPath("$.blocked.byLatestStatus[0].key").value("BLOCKED"))
                .andExpect(jsonPath("$.agents.lastAt.callLimit").value("2026-11-17T01:02:00Z"))
                .andExpect(jsonPath("$.system.missingMethodDecision").value("PERMIT"))
                .andExpect(jsonPath("$.attention.rows[0].signals[1].count").value(6))
                .andExpect(jsonPath("$.attention.capped").value(false))
                .andExpect(jsonPath("$.changes.recent[0].action").value("POLICY_APPROVED"))
                .andExpect(jsonPath("$.denials.resources[0].key").value("/api/payroll/export"))
                .andExpect(jsonPath("$.operations.components").isArray());
    }

    @Test
    void noPeriodIsTheDefaultAndAnUnknownOneIsABadRequest() throws Exception {
        when(service.dashboard(isNull(), any())).thenReturn(answer("week"));
        mvc.perform(get("/contexa/admin/api/dashboard").principal(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.period.key").value("week"));
        when(service.dashboard(eq("year"), any())).thenThrow(new IllegalArgumentException("not a period"));
        mvc.perform(get("/contexa/admin/api/dashboard").param("period", "year").principal(admin))
                .andExpect(status().isBadRequest());
    }

    static DashboardView answer(String period) {
        return new DashboardView(new Period(period, "2026-11-10T04:20:00Z", "2026-11-17T04:20:00Z"), null,
                new OperationsPart(List.of()),
                new PolicyPart(412, 318, 41, 29, 146, 139, 3, 141, 2, "WARNING", 1, 2,
                        List.of(new DayCount("2026-11-11", 1)), 17),
                new IamPart(3412, 48, 26, 384, 3300, 3071, 4, 2, 37, 3, 214, 12, true),
                new SecurityPart(1184, List.of(new DayCount("2026-11-11", 176)), 3, 0, 12, 412),
                new BlockedPart(8, List.of(new Count("BLOCKED", 4))),
                new AgentsPart(List.of(new Count("ACTIVE", 23)), 41, 4, 1, 7, 1, 1, 1,
                        Map.of("callLimit", "2026-11-17T01:02:00Z")),
                new SystemPart("ENFORCE", "2026-11-03T00:00:00Z", null, "FIRST_APPLICABLE", "PERMIT", "AUTHENTICATED",
                        90, false),
                new AttentionPart(23, false, List.of(new AttentionRow("park.jiwoo",
                        List.of(new Signal("BLOCKED", null), new Signal("CHALLENGES", 6L)), "2026-11-17T03:41:00Z",
                        "req-7f3a91"))),
                new ChangesPart(List.of(new Count("POLICY", 7)), List.of(new ChangeRow("2026-11-17T02:02:00Z",
                        "policy.owner", "POLICY", "POLICY_APPROVED", "Payment approval window"))),
                new DenialsPart(612, List.of(new Count("/api/payroll/export", 142)), List.of()));
    }
}
