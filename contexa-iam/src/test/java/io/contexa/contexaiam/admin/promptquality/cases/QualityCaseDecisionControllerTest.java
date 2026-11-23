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
package io.contexa.contexaiam.admin.promptquality.cases;

import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Evaluation;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.EvaluationSaved;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Quality plan 3.6: in the decision detail, an administrator evaluates a decision and makes it a case in one step, kept
 * in the platform's scope; the case says whether the second analysis decided it. A decision not sealed, an evaluation
 * that says neither valid nor invalid, an answer that is no case and cases that are not here are refused with their
 * reason; the call is an administrator's alone.
 */
class QualityCaseDecisionControllerTest {

    private static final String PATH = "/contexa/admin/api/zero-trust/decisions/obs-1/case";
    private static final String ANSWER = "{\"allowedActions\":[\"BLOCK\"],\"classification\":\"THREAT\","
            + "\"kind\":\"OUTSIDER\",\"rationale\":\"stolen account\",\"grade\":\"MUST_CATCH\"}";
    private final Authentication admin = new TestingAuthenticationToken("admin-a", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
    private final Authentication user = new TestingAuthenticationToken("user", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_USER"));
    private final QualityCasePromotions promotions = mock(QualityCasePromotions.class);
    private final AtomicReference<QualityCasePromotions> promoting = new AtomicReference<>(promotions);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new QualityCaseDecisionController(promoting::get))
            .build();

    QualityCaseDecisionControllerTest() {
        admin.setAuthenticated(true);
        user.setAuthenticated(true);
    }

    @Test
    void aDecisionIsEvaluatedAndMadeACaseInOneStep() throws Exception {
        PromptQualityCases.Kept kept = mock(PromptQualityCases.Kept.class);
        when(kept.key()).thenReturn("op-3");
        when(kept.status()).thenReturn(PromptQualityCases.CONFIRMED);
        when(kept.secondAnalysis()).thenReturn(true);
        when(promotions.fromEvaluation(any(), any(), any(), any(), any(), any())).thenReturn(
                new QualityCasePromotions.Promoted(kept, "package-1", "obs-1",
                        new EvaluationSaved("outcome-1", "obs-1", "EVALUATED_INVALID")));

        mvc.perform(post(PATH).principal(admin).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"evaluation\":{\"valid\":false,\"reason\":\"MISSED_SIGNAL\",\"note\":\"seen later\"},"
                                + "\"answer\":" + ANSWER + "}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.caseKey").value("op-3"))
                .andExpect(jsonPath("$.status").value(PromptQualityCases.CONFIRMED))
                .andExpect(jsonPath("$.secondAnalysis").value(true))
                .andExpect(jsonPath("$.evaluation").value("EVALUATED_INVALID"))
                .andExpect(jsonPath("$.sealedPackageId").value("package-1"));
        ArgumentCaptor<Evaluation> evaluation = ArgumentCaptor.forClass(Evaluation.class);
        verify(promotions).fromEvaluation(isNull(), eq("obs-1"), evaluation.capture(), any(),
                eq(QualityCaseGrade.MUST_CATCH), eq("admin-a"));
        assertThat(evaluation.getValue()).isEqualTo(new Evaluation(false, "MISSED_SIGNAL", "seen later"));
    }

    @Test
    void aDecisionThatCannotBeACaseIsRefusedWithItsReason() throws Exception {
        when(promotions.fromEvaluation(any(), eq("obs-1"), any(), any(), any(), any())).thenThrow(
                new PromptQualityCases.RefusedException(PromptQualityCases.Refusal.NOT_SEALED, "not sealed"));
        mvc.perform(post(PATH).principal(admin).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"evaluation\":{\"valid\":true},\"answer\":" + ANSWER + "}"))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.refusal").value("NOT_SEALED"));

        when(promotions.fromEvaluation(any(), eq("obs-2"), any(), any(), any(), any())).thenThrow(
                new IllegalArgumentException("An evaluation says whether the decision was valid"));
        mvc.perform(post("/contexa/admin/api/zero-trust/decisions/obs-2/case").principal(admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"evaluation\":{},\"answer\":" + ANSWER + "}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.refusal").value("INVALID"));
        for (String broken : List.of("{\"answer\":" + ANSWER + "}", "{\"evaluation\":{\"valid\":true}}",
                "{\"evaluation\":{\"valid\":true},\"answer\":{\"allowedActions\":[\"BLOCK\"],\"classification\":"
                        + "\"THREAT\",\"kind\":\"SPY\",\"rationale\":\"x\"}}")) {
            mvc.perform(post(PATH).principal(admin).contentType(MediaType.APPLICATION_JSON).content(broken))
                    .andExpect(status().isBadRequest()).andExpect(jsonPath("$.refusal").value("INVALID"));
        }
        promoting.set(null);
        mvc.perform(post(PATH).principal(admin).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"evaluation\":{\"valid\":true},\"answer\":" + ANSWER + "}"))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.refusal").value("UNAVAILABLE"));
    }

    @Test
    void theCaseOfADecisionIsAnAdministratorsAlone() throws Exception {
        mvc.perform(post(PATH).principal(user).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isForbidden());
        mvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isForbidden());
        verifyNoInteractions(promotions);
    }
}
