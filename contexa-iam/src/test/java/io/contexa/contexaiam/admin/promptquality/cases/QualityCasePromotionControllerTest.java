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

import io.contexa.contexacore.std.components.prompt.quality.QualityAction;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseClass;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseExpectation;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseKind;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Quality plan 3.6: in the result of a trial, the sealed decisions the two versions decided differently are listed and
 * one is made a case with the answer set, by an administrator; an answer that is no case, a decision the versions did
 * not decide apart, one not sealed, and cases that are not here are refused with their reason. The answer of a case is
 * read the same way on every screen.
 */
class QualityCasePromotionControllerTest {

    private static final String ANSWER = "{\"allowedActions\":[\"CHALLENGE\",\"block\"],\"preferredAction\":\"BLOCK\","
            + "\"classification\":\"threat\",\"kind\":\"OUTSIDER\",\"rationale\":\"Another person's account\","
            + "\"grade\":\"MUST_CATCH\"}";
    private final Authentication admin = new TestingAuthenticationToken("admin-a", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
    private final Authentication user = new TestingAuthenticationToken("user", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_USER"));
    private final QualityCasePromotions promotions = mock(QualityCasePromotions.class);
    private final AtomicReference<QualityCasePromotions> promoting = new AtomicReference<>(promotions);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new QualityCasePromotionController(promoting::get))
            .build();

    QualityCasePromotionControllerTest() {
        admin.setAuthenticated(true);
        user.setAuthenticated(true);
    }

    @Test
    void theDecisionsTheTwoVersionsDecidedApartAreListed() throws Exception {
        when(promotions.divergent(7L)).thenReturn(List.of(new QualityCasePromotions.Divergent("package-d", "request-d",
                "obs-d", "ALLOW", "BLOCK")));

        mvc.perform(get(QualityCasePromotionController.TRIALS + "/7/divergent").principal(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].sealedPackageId").value("package-d"))
                .andExpect(jsonPath("$[0].observationId").value("obs-d"))
                .andExpect(jsonPath("$[0].candidateAction").value("BLOCK"));
        when(promotions.divergent(8L)).thenThrow(new PromptQualityCases.RefusedException(
                PromptQualityCases.Refusal.NOT_FOUND, "There is no trial 8"));
        mvc.perform(get(QualityCasePromotionController.TRIALS + "/8/divergent").principal(admin))
                .andExpect(status().isNotFound()).andExpect(jsonPath("$.refusal").value("NOT_FOUND"));
    }

    @Test
    void aDecisionOfTheTrialIsMadeACaseWithTheAnswerSet() throws Exception {
        PromptQualityCases.Kept kept = mock(PromptQualityCases.Kept.class);
        when(kept.key()).thenReturn("op-9");
        when(kept.status()).thenReturn(PromptQualityCases.PENDING);
        when(kept.secondAnalysis()).thenReturn(true);
        when(promotions.fromTrial(anyLong(), any(), any(), any(), any())).thenReturn(new QualityCasePromotions.Promoted(
                kept, "package-d", "obs-d", null));

        mvc.perform(post(QualityCasePromotionController.TRIALS + "/7/cases").principal(admin).locale(Locale.ENGLISH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"packageId\":\" package-d \",\"answer\":" + ANSWER + "}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.caseKey").value("op-9"))
                .andExpect(jsonPath("$.status").value(PromptQualityCases.PENDING))
                .andExpect(jsonPath("$.observationId").value("obs-d"))
                .andExpect(jsonPath("$.secondAnalysis").value(true));
        ArgumentCaptor<QualityCaseExpectation> answer = ArgumentCaptor.forClass(QualityCaseExpectation.class);
        verify(promotions).fromTrial(eq(7L), eq("package-d"), answer.capture(), eq(QualityCaseGrade.MUST_CATCH),
                eq("admin-a"));
        assertThat(answer.getValue().allowedActions()).isEqualTo(EnumSet.of(QualityAction.CHALLENGE,
                QualityAction.BLOCK));
        assertThat(answer.getValue().rationale().english()).isEqualTo("Another person's account");
        assertThat(answer.getValue().rationale().korean()).isNull();
    }

    @Test
    void aDecisionThatCannotBeACaseIsRefusedWithItsReason() throws Exception {
        when(promotions.fromTrial(eq(7L), eq("package-s"), any(), any(), any())).thenThrow(
                new PromptQualityCases.RefusedException(PromptQualityCases.Refusal.NOT_DIVERGENT, "not divergent"));
        when(promotions.fromTrial(eq(7L), eq("package-gone"), any(), any(), any())).thenThrow(
                new PromptQualityCases.RefusedException(PromptQualityCases.Refusal.NOT_SEALED, "not sealed"));
        for (String[] refused : List.of(new String[]{"package-s", "NOT_DIVERGENT"},
                new String[]{"package-gone", "NOT_SEALED"})) {
            mvc.perform(post(QualityCasePromotionController.TRIALS + "/7/cases").principal(admin)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"packageId\":\"" + refused[0] + "\",\"answer\":" + ANSWER + "}"))
                    .andExpect(status().isConflict()).andExpect(jsonPath("$.refusal").value(refused[1]));
        }
        for (String broken : List.of("{\"answer\":" + ANSWER + "}", "{\"packageId\":\"package-d\"}",
                "{\"packageId\":\"package-d\",\"answer\":{\"allowedActions\":[],\"classification\":\"THREAT\","
                        + "\"kind\":\"OUTSIDER\",\"rationale\":\"x\"}}")) {
            mvc.perform(post(QualityCasePromotionController.TRIALS + "/7/cases").principal(admin)
                            .contentType(MediaType.APPLICATION_JSON).content(broken))
                    .andExpect(status().isBadRequest()).andExpect(jsonPath("$.refusal").value("INVALID"));
        }
        promoting.set(null);
        mvc.perform(post(QualityCasePromotionController.TRIALS + "/7/cases").principal(admin)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"packageId\":\"package-d\",\"answer\":"
                                + ANSWER + "}"))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.refusal").value("UNAVAILABLE"));
        mvc.perform(get(QualityCasePromotionController.TRIALS + "/7/divergent").principal(admin))
                .andExpect(status().isServiceUnavailable());
    }

    @Test
    void theTrialsCasesAreAnAdministratorsAlone() throws Exception {
        mvc.perform(get(QualityCasePromotionController.TRIALS + "/7/divergent").principal(user))
                .andExpect(status().isForbidden());
        mvc.perform(post(QualityCasePromotionController.TRIALS + "/7/cases").principal(user)
                .contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
        verifyNoInteractions(promotions);
    }

    /** The answer of a case: its reason in the language it is written in, an ordinary grade unless one is given. */
    @Test
    void theAnswerOfACaseIsReadTheSameWayOnEveryScreen() {
        QualityCaseAnswerForm form = new QualityCaseAnswerForm(List.of("allow"), null, "normal", "normal_work",
                "평소 업무", null);

        QualityCaseExpectation expectation = form.expectation(Locale.KOREAN);

        assertThat(expectation.allowedActions()).containsExactly(QualityAction.ALLOW);
        assertThat(expectation.classification()).isEqualTo(QualityCaseClass.NORMAL);
        assertThat(expectation.kind()).isEqualTo(QualityCaseKind.NORMAL_WORK);
        assertThat(expectation.rationale().korean()).isEqualTo("평소 업무");
        assertThat(form.caseGrade()).isEqualTo(QualityCaseGrade.ORDINARY);
        assertThatThrownBy(() -> new QualityCaseAnswerForm(List.of("APPROVE"), null, "NORMAL", "NORMAL_WORK", "x", null)
                .expectation(Locale.KOREAN)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new QualityCaseAnswerForm(List.of("ALLOW"), "BLOCK", "NORMAL", "NORMAL_WORK", "x",
                null).expectation(Locale.KOREAN)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new QualityCaseAnswerForm(List.of("ALLOW"), null, "NORMAL", "NORMAL_WORK", " ", null)
                .expectation(Locale.ENGLISH)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new QualityCaseAnswerForm(List.of("ALLOW"), null, "NORMAL", "NORMAL_WORK", "x", "TOP")
                .caseGrade()).isInstanceOf(IllegalArgumentException.class);
    }
}
