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
package io.contexa.contexaiam.admin.promptquality.evidence;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.quality.QualityAction;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseClass;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseExpectation;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseKind;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCasePromotions;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityNav;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityNavAdvice;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityNavCounts;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityScreens;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleController;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.ControllerAdvice;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * Quality plan 3.7, 3.8: the sealed evidence opens its list and a decision for an administrator only, with the menu
 * bar and the addresses its script calls; its list reads the period asked for (the last 7 days without one) with the
 * filter; a decision missing is not found; a sealed decision is made a case with the answer set, and a decision not
 * sealed, an answer that is no case or cases that are not here are refused with their reason.
 */
class SealedEvidenceControllerTest {

    private static final Instant NOW = Instant.parse("2026-11-22T12:00:00Z");
    private final Authentication admin = new TestingAuthenticationToken("admin-a", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
    private final Authentication user = new TestingAuthenticationToken("user", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_USER"));
    private final JdbcPromptInspectionQueries queries = mock(JdbcPromptInspectionQueries.class);
    private final SealedEvidenceDetails details = mock(SealedEvidenceDetails.class);
    private final QualityCasePromotions promotions = mock(QualityCasePromotions.class);
    private final AtomicReference<QualityCasePromotions> promoting = new AtomicReference<>(promotions);
    private final MockMvc mvc;

    SealedEvidenceControllerTest() {
        admin.setAuthenticated(true);
        user.setAuthenticated(true);
        StaticMessageSource messages = new StaticMessageSource();
        messages.addMessage("pqa.evidence.list.title", Locale.KOREAN, "봉인 목록");
        PromptQualityNavCounts counts = new PromptQualityNavCounts(() -> null, () -> null, () -> null, () -> null,
                () -> null, null);
        mvc = MockMvcBuilders.standaloneSetup(new SealedEvidenceController(queries, details, promoting::get, messages,
                        new ObjectMapper(), Clock.fixed(NOW, ZoneOffset.UTC)))
                .setControllerAdvice(new PromptQualityNavAdvice(counts)).build();
    }

    @Test
    void theListAndADecisionOpenForAnAdministratorWithTheBarAndTheAddressesTheScriptCalls() throws Exception {
        for (String address : List.of(PromptQualityScreens.EVIDENCE, PromptQualityScreens.EVIDENCE + "/")) {
            MvcResult result = mvc.perform(get(address).principal(admin).locale(Locale.KOREAN))
                    .andExpect(status().isOk())
                    .andExpect(view().name("contexa/admin/prompt-quality/evidence"))
                    .andExpect(model().attribute("screen", "evidence"))
                    .andExpect(model().attribute("activePage", "prompt-quality-evidence"))
                    .andExpect(model().attribute("apiBase", SealedEvidenceController.API))
                    .andExpect(model().attribute("pagesBase", PromptQualityScreens.EVIDENCE))
                    .andExpect(model().attribute("inspectionApi", "/contexa/admin/api/prompt-inspection"))
                    .andExpect(model().attribute("replayApi", "/contexa/admin/api/sealed-decisions"))
                    .andReturn();
            assertThat(result.getModelAndView().getModel().get("packageId")).isNull();
            assertThat(result.getModelAndView().getModel().get(PromptQualityNavAdvice.ATTRIBUTE))
                    .isInstanceOf(PromptQualityNav.class);
            assertThat((String) result.getModelAndView().getModel().get("scriptMessagesJson"))
                    .contains("\"pqa.evidence.list.title\":\"봉인 목록\"");
        }
        mvc.perform(get(PromptQualityScreens.EVIDENCE + "/p-1").principal(admin))
                .andExpect(status().isOk())
                .andExpect(view().name("contexa/admin/prompt-quality/evidence"))
                .andExpect(model().attribute("packageId", "p-1"));
    }

    @Test
    void theListReadsThePeriodAskedForWithTheFilterOrTheLastSevenDays() throws Exception {
        when(queries.evidence(any(), anyInt(), anyInt())).thenReturn(new JdbcPromptInspectionQueries.EvidencePage(1, 2,
                20, List.of(new JdbcPromptInspectionQueries.EvidenceRow("p-1", NOW, "alice", "GET", "/a", "BLOCK",
                "v1.0", "MISMATCH", "OK", "UNCHECKED", "FAIL", 1, 2, "prompt-inspector/31", NOW)),
                new JdbcPromptInspectionQueries.EvidenceTotals(1, 1, 0, 1, 0, 0), List.of("v1.0")));

        mvc.perform(get(SealedEvidenceController.API).param("from", "2026-11-01T00:00:00Z")
                        .param("to", "2026-11-08T00:00:00Z").param("action", "BLOCK").param("version", "v1.0")
                        .param("result", "PROBLEM").param("user", "alice").param("q", "/a").param("block", "REQUEST")
                        .param("entry", "Action").param("verdict", "FAIL").param("checkCode", "SOURCE_TRUTH")
                        .param("page", "2").param("size", "20").principal(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rows[0].packageId").value("p-1"))
                .andExpect(jsonPath("$.rows[0].integrity").value("MISMATCH"))
                .andExpect(jsonPath("$.rows[0].verdict").value("FAIL"))
                .andExpect(jsonPath("$.rows[0].mismatchCount").value(1))
                .andExpect(jsonPath("$.rows[0].unverifiableCount").value(2))
                .andExpect(jsonPath("$.rows[0].inspectorVersion").value("prompt-inspector/31"))
                .andExpect(jsonPath("$.rows[0].inspectedAt").exists())
                .andExpect(jsonPath("$.totals.sealed").value(1))
                .andExpect(jsonPath("$.versions[0]").value("v1.0"));
        verify(queries).evidence(new JdbcPromptInspectionQueries.EvidenceFilter(Instant.parse("2026-11-01T00:00:00Z"),
                Instant.parse("2026-11-08T00:00:00Z"), "BLOCK", "v1.0", "PROBLEM", "alice", "/a", "REQUEST", "Action",
                "FAIL", "SOURCE_TRUTH"), 2, 20);

        mvc.perform(get(SealedEvidenceController.API).principal(admin)).andExpect(status().isOk());
        ArgumentCaptor<JdbcPromptInspectionQueries.EvidenceFilter> filter =
                ArgumentCaptor.forClass(JdbcPromptInspectionQueries.EvidenceFilter.class);
        verify(queries).evidence(filter.capture(), eq(0), eq(20));
        assertThat(filter.getValue().to()).isEqualTo(NOW);
        assertThat(filter.getValue().from()).isEqualTo(NOW.minus(Duration.ofDays(7)));
    }

    @Test
    void aPeriodThatEndsBeforeItStartsOrAResultUnknownIsABadRequest() throws Exception {
        mvc.perform(get(SealedEvidenceController.API).param("from", "2026-11-08T00:00:00Z")
                .param("to", "2026-11-01T00:00:00Z").principal(admin)).andExpect(status().isBadRequest());
        when(queries.evidence(any(), anyInt(), anyInt())).thenThrow(new IllegalArgumentException("Unknown audit result"));
        mvc.perform(get(SealedEvidenceController.API).param("result", "BROKEN").principal(admin))
                .andExpect(status().isBadRequest());
    }

    @Test
    void aDecisionIsReadOrNotFound() throws Exception {
        when(details.detail("missing")).thenReturn(Optional.empty());
        mvc.perform(get(SealedEvidenceController.API + "/missing").principal(admin)).andExpect(status().isNotFound());
    }

    @Test
    void aSealedDecisionIsMadeACaseWithTheAnswerSet() throws Exception {
        PromptQualityCases.Kept kept = mock(PromptQualityCases.Kept.class);
        when(kept.key()).thenReturn("op-1");
        when(kept.status()).thenReturn(PromptQualityCases.PENDING);
        when(promotions.fromSealed(any(), any(), any(), any(), any())).thenReturn(new QualityCasePromotions.Promoted(
                kept, "p-1", null, null));

        mvc.perform(post(SealedEvidenceController.API + "/p-1/case").param("scope", "tenant-a").principal(admin)
                        .locale(Locale.KOREAN).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"allowedActions\":[\"CHALLENGE\",\"block\"],\"preferredAction\":\"BLOCK\","
                                + "\"classification\":\"threat\",\"kind\":\"OUTSIDER\",\"rationale\":\"다른 사람의 계정\","
                                + "\"grade\":\"MUST_CATCH\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.caseKey").value("op-1"))
                .andExpect(jsonPath("$.status").value(PromptQualityCases.PENDING))
                .andExpect(jsonPath("$.sealedPackageId").value("p-1"));
        ArgumentCaptor<QualityCaseExpectation> answer = ArgumentCaptor.forClass(QualityCaseExpectation.class);
        verify(promotions).fromSealed(eq("tenant-a"), eq("p-1"), answer.capture(), eq(QualityCaseGrade.MUST_CATCH),
                eq("admin-a"));
        assertThat(answer.getValue().allowedActions()).isEqualTo(EnumSet.of(QualityAction.CHALLENGE,
                QualityAction.BLOCK));
        assertThat(answer.getValue().preferredAction()).isEqualTo(QualityAction.BLOCK);
        assertThat(answer.getValue().classification()).isEqualTo(QualityCaseClass.THREAT);
        assertThat(answer.getValue().kind()).isEqualTo(QualityCaseKind.OUTSIDER);
        assertThat(answer.getValue().rationale().korean()).isEqualTo("다른 사람의 계정");
        assertThat(answer.getValue().rationale().english()).isNull();
    }

    @Test
    void aDecisionNotSealedAnAnswerThatIsNoCaseOrNoCasesAreRefusedWithTheirReason() throws Exception {
        String answer = "{\"allowedActions\":[\"ALLOW\"],\"classification\":\"NORMAL\",\"kind\":\"NORMAL_WORK\","
                + "\"rationale\":\"usual work\"}";
        when(promotions.fromSealed(any(), eq("loose"), any(), any(), any())).thenThrow(
                new PromptQualityCases.RefusedException(PromptQualityCases.Refusal.NOT_SEALED, "not sealed"));
        mvc.perform(post(SealedEvidenceController.API + "/loose/case").principal(admin)
                        .contentType(MediaType.APPLICATION_JSON).content(answer))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.refusal").value("NOT_SEALED"));

        for (String broken : List.of("{\"allowedActions\":[],\"classification\":\"NORMAL\",\"kind\":\"NORMAL_WORK\","
                        + "\"rationale\":\"x\"}",
                "{\"allowedActions\":[\"ALLOW\"],\"classification\":\"NOPE\",\"kind\":\"NORMAL_WORK\",\"rationale\":\"x\"}",
                "{\"allowedActions\":[\"ALLOW\"],\"classification\":\"NORMAL\",\"kind\":\"NORMAL_WORK\"}",
                "{\"allowedActions\":[\"ALLOW\"],\"preferredAction\":\"BLOCK\",\"classification\":\"NORMAL\","
                        + "\"kind\":\"NORMAL_WORK\",\"rationale\":\"x\"}")) {
            mvc.perform(post(SealedEvidenceController.API + "/p-1/case").principal(admin)
                            .contentType(MediaType.APPLICATION_JSON).content(broken))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.refusal").value("INVALID"));
        }

        promoting.set(null);
        mvc.perform(post(SealedEvidenceController.API + "/p-1/case").principal(admin)
                        .contentType(MediaType.APPLICATION_JSON).content(answer))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.refusal").value("UNAVAILABLE"));
    }

    @Test
    void theScreenItsDataAndItsCasesAreAnAdministratorsAlone() throws Exception {
        for (String address : List.of(PromptQualityScreens.EVIDENCE, PromptQualityScreens.EVIDENCE + "/p-1",
                SealedEvidenceController.API, SealedEvidenceController.API + "/p-1")) {
            mvc.perform(get(address).principal(user)).andExpect(status().isForbidden());
            mvc.perform(get(address)).andExpect(status().isForbidden());
        }
        mvc.perform(post(SealedEvidenceController.API + "/p-1/case").principal(user)
                .contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
        verifyNoInteractions(queries, details, promotions);
        assertThat(SealedEvidenceController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo(PromptVersionConsoleController.class.getAnnotation(PreAuthorize.class).value());
        String[] packages = PromptQualityNavAdvice.class.getAnnotation(ControllerAdvice.class).basePackages();
        assertThat(SealedEvidenceController.class.getPackageName()).startsWith(packages[0] + ".");
    }
}
