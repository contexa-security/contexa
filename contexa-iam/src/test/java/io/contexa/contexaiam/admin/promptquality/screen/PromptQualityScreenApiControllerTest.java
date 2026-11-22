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

import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.Saved;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.EstimateView;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Quality plan 3.2, 3.3: the JSON of the labelled cases and of measure and compare is an administrator's; every change
 * is a POST the console's CSRF protection covers; a request without what it needs is a bad request; a change the
 * services refuse answers 422 with the code the screens name (NOT_SEALED, SELF_CONFIRMATION, CALL_LIMIT, ...).
 */
class PromptQualityScreenApiControllerTest {

    private static final String CASES = "/contexa/admin/api/prompt-quality/cases";
    private static final String MEASURE = "/contexa/admin/api/prompt-quality/measure";
    private static final String ANSWER = "{\"allowedActions\":[\"BLOCK\"],\"classification\":\"THREAT\","
            + "\"kind\":\"OUTSIDER\",\"rationaleKo\":\"차단\",\"grade\":\"ORDINARY\"}";

    private final PromptQualityCaseScreen cases = mock(PromptQualityCaseScreen.class);
    private final PromptQualityMeasureScreen measure = mock(PromptQualityMeasureScreen.class);
    private final Authentication admin = new UsernamePasswordAuthenticationToken("admin", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
    private final Authentication user = new UsernamePasswordAuthenticationToken("alice", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_USER"));
    private final HttpSessionCsrfTokenRepository csrf = new HttpSessionCsrfTokenRepository();
    private MockMvc mvc;
    private MockHttpSession session;
    private CsrfToken token;

    @BeforeEach
    void setUp() {
        CsrfFilter filter = new CsrfFilter(csrf);
        filter.setRequestHandler(new CsrfTokenRequestAttributeHandler());
        mvc = MockMvcBuilders.standaloneSetup(new PromptQualityCaseApiController(cases),
                new PromptQualityMeasureApiController(measure)).addFilters(filter).build();
        session = new MockHttpSession();
        MockHttpServletRequest seed = new MockHttpServletRequest();
        seed.setSession(session);
        token = csrf.generateToken(seed);
        csrf.saveToken(token, seed, new MockHttpServletResponse());
    }

    private MockHttpServletRequestBuilder withToken(MockHttpServletRequestBuilder request) {
        return request.session(session).header(token.getHeaderName(), token.getToken());
    }

    @Test
    void theJsonIsAnAdministratorsAlone() throws Exception {
        for (String read : List.of(CASES, CASES + "/A1", CASES + "/A1/input", MEASURE, MEASURE + "/band",
                MEASURE + "/estimate?version=2", MEASURE + "/run", MEASURE + "/3", MEASURE + "/compare",
                MEASURE + "/compare/answers?case=A1")) {
            mvc.perform(get(read).principal(user)).andExpect(status().isForbidden());
            mvc.perform(get(read)).andExpect(status().isForbidden());
        }
        for (String change : List.of(CASES, CASES + "/promote", CASES + "/A1/answer", CASES + "/A1/confirm",
                CASES + "/A1/delete", CASES + "/publish", MEASURE, MEASURE + "/3/cancel")) {
            mvc.perform(withToken(post(change)).principal(user).contentType("application/json").content("{}"))
                    .andExpect(status().isForbidden());
        }
        verify(cases, never()).publish(any(), any());
        verify(measure, never()).start(any(), any(), any(), any(), any());
        assertThat(PromptQualityCaseApiController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo(PromptQualityMeasureApiController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo("hasAuthority('ROLE_ADMIN')");
    }

    /** Every change needs the console's CSRF token. */
    @Test
    void aChangeWithoutTheCsrfTokenIsRefused() throws Exception {
        for (String change : List.of(CASES, CASES + "/promote", CASES + "/A1/answer", CASES + "/A1/confirm",
                CASES + "/A1/delete", CASES + "/publish", MEASURE, MEASURE + "/3/cancel")) {
            mvc.perform(post(change).principal(admin).contentType("application/json").content("{}"))
                    .andExpect(status().isForbidden());
        }
        verify(cases, never()).confirm(any(), any(), any());
        verify(cases, never()).delete(any(), any(), any());
        verify(measure, never()).cancel(anyLong(), any());
    }

    @Test
    void aRequestWithoutWhatItNeedsIsABadRequest() throws Exception {
        mvc.perform(withToken(post(CASES)).principal(admin).contentType("application/json")
                .content("{\"sourceKey\":\"A1\"}")).andExpect(status().isBadRequest());
        mvc.perform(withToken(post(CASES + "/promote")).principal(admin).contentType("application/json")
                .content("{\"packageId\":\"p-1\"}")).andExpect(status().isBadRequest());
        mvc.perform(withToken(post(MEASURE)).principal(admin).contentType("application/json").content("{}"))
                .andExpect(status().isBadRequest());
        mvc.perform(get(MEASURE).param("page", "-1").principal(admin)).andExpect(status().isBadRequest());
        mvc.perform(get(MEASURE + "/estimate").principal(admin)).andExpect(status().isBadRequest());
        mvc.perform(get(MEASURE + "/compare/answers").principal(admin)).andExpect(status().isBadRequest());
        mvc.perform(get(CASES + "/A1%20B").principal(admin)).andExpect(status().isNotFound());
        verify(cases, never()).create(any(), any(), any(), any(), any());
        verify(cases, never()).promote(any(), any(), any(), any());
    }

    /** A refusal answers 422 with the code the screens put in the reader's words. */
    @Test
    void aRefusalAnswersItsCode() throws Exception {
        when(cases.promote(any(), eq("p-missing"), any(), eq("admin"))).thenThrow(new PromptQualityCaseScreen
                .RefusedException(PromptQualityCaseScreen.NOT_SEALED, "not sealed"));
        mvc.perform(withToken(post(CASES + "/promote")).principal(admin).contentType("application/json")
                        .content("{\"packageId\":\"p-missing\",\"answer\":" + ANSWER + "}"))
                .andExpect(status().isUnprocessableEntity()).andExpect(jsonPath("$.code").value("NOT_SEALED"));
        when(cases.confirm(any(), eq("operation-3"), eq("admin"))).thenThrow(new PromptQualityCases.RefusedException(
                PromptQualityCases.Refusal.SELF_CONFIRMATION, "self"));
        mvc.perform(withToken(post(CASES + "/operation-3/confirm")).principal(admin))
                .andExpect(status().isUnprocessableEntity()).andExpect(jsonPath("$.code").value("SELF_CONFIRMATION"));
        when(cases.changeAnswer(any(), eq("A1"), any(), eq("admin"))).thenThrow(new PromptQualityCases
                .RefusedException(PromptQualityCases.Refusal.READ_ONLY, "read only"));
        mvc.perform(withToken(post(CASES + "/A1/answer")).principal(admin).contentType("application/json")
                .content(ANSWER)).andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.code").value("READ_ONLY"));
        when(measure.start(any(), eq(2), isNull(), eq(10), eq("admin"))).thenThrow(new PromptQualityMeasurements
                .RefusedException(PromptQualityMeasurements.Refusal.CALL_LIMIT, "limit"));
        mvc.perform(withToken(post(MEASURE)).principal(admin).contentType("application/json")
                        .content("{\"version\":2,\"repeats\":10}"))
                .andExpect(status().isUnprocessableEntity()).andExpect(jsonPath("$.code").value("CALL_LIMIT"));
        when(measure.start(any(), eq(3), any(), any(), any())).thenThrow(new PromptQualityMeasureScreen
                .RefusedException(PromptQualityMeasureScreen.NO_RUNNER, "none"));
        mvc.perform(withToken(post(MEASURE)).principal(admin).contentType("application/json")
                .content("{\"version\":3}")).andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.code").value("NO_RUNNER"));
    }

    @Test
    void theChangesAndReadsReachTheScreensWithTheAdministratorAndTheScope() throws Exception {
        when(cases.confirm("tenant-a", "operation-3", "admin")).thenReturn(new Saved("operation-3", "CONFIRMED"));
        mvc.perform(withToken(post(CASES + "/operation-3/confirm")).param("scope", "tenant-a").principal(admin))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("CONFIRMED"));
        when(measure.start(null, 2, 5L, 3, "admin")).thenReturn(41L);
        mvc.perform(withToken(post(MEASURE)).principal(admin).contentType("application/json")
                .content("{\"version\":2,\"caseSet\":5,\"repeats\":3}")).andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(41));
        when(measure.estimate(null, 2, null, 4)).thenReturn(new EstimateView(70, 4, 280, 0, 280, 280, 3360, 3000,
                true, 33, null));
        mvc.perform(get(MEASURE + "/estimate").param("version", "2").param("repeats", "4").principal(admin))
                .andExpect(status().isOk()).andExpect(jsonPath("$.minutes").value(33));
        when(measure.run(null, 9L)).thenReturn(Optional.empty());
        mvc.perform(get(MEASURE + "/9").principal(admin)).andExpect(status().isNotFound());
        when(cases.detail(any(), eq("A9"), eq("admin"), any(Locale.class))).thenReturn(Optional.empty());
        mvc.perform(get(CASES + "/A9").principal(admin)).andExpect(status().isNotFound());
        when(measure.caseAnswers(null, 3, 1, null, null, "A1")).thenReturn(Optional.empty());
        mvc.perform(get(MEASURE + "/compare/answers").param("candidate", "3").param("reference", "1")
                .param("case", "A1").principal(admin)).andExpect(status().isNotFound());
        verify(measure).caseAnswers(null, 3, 1, null, null, "A1");
        mvc.perform(get(MEASURE + "/compare").param("candidate", "3").param("reference", "1").principal(admin))
                .andExpect(status().isOk());
        verify(measure).compare(null, 3, 1, null, null);
        // Two measurements by their ids (the scheduled measurement's comparison) reach the screen with the versions.
        mvc.perform(get(MEASURE + "/compare").param("candidateMeasure", "9").param("referenceMeasure", "8")
                .param("candidate", "3").principal(admin)).andExpect(status().isOk());
        verify(measure).compare(null, 3, null, 9L, 8L);
        mvc.perform(get(MEASURE + "/compare").param("candidateMeasure", "x").principal(admin))
                .andExpect(status().isBadRequest());
        verify(measure, never()).cancel(anyLong(), eq("alice"));
        verify(measure, never()).estimate(any(), anyInt(), any(), eq(0));
    }
}
