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
package io.contexa.contexacore.hcad.filter;

import io.contexa.contexacore.hcad.evaluation.HcadEvaluationWriter;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAssessment;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAttributes;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionBand;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionScorer;
import io.contexa.contexacore.hcad.projection.TrustedHcadContextProjection;
import io.contexa.contexacore.hcad.projection.TrustedHcadContextProjectionFactory;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyTriggerAttributes;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyTriggerOrchestrator;
import io.contexa.contexacore.hcad.trigger.HcadPreTriggerMode;
import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class HCADFilterTest {

    @Mock
    private TrustedHcadContextProjectionFactory trustedProjectionFactory;

    @Mock
    private HcadPreProtectablePromotionScorer preProtectablePromotionScorer;

    @Mock
    private PendingAnomalyTriggerOrchestrator pendingAnomalyTriggerOrchestrator;

    @Mock
    private HcadEvaluationWriter hcadEvaluationWriter;

    private HCADFilter hcadFilter;
    private HcadProperties hcadProperties;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain filterChain;

    @BeforeEach
    void setUp() {
        hcadProperties = new HcadProperties();
        hcadFilter = new HCADFilter(
                trustedProjectionFactory,
                preProtectablePromotionScorer,
                hcadProperties,
                pendingAnomalyTriggerOrchestrator);
        request = new MockHttpServletRequest();
        request.setRequestURI("/api/test");
        response = new MockHttpServletResponse();
        filterChain = new MockFilterChain();
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("trusted HCAD projection assessment should be projected onto request attributes")
    void doFilterInternal_trustedProjection_storesAssessmentInRequest() throws Exception {
        setAuthenticated();
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                72,
                HcadPreProtectablePromotionBand.REDLINE,
                true,
                List.of("FAILED_LOGIN_BURST"),
                List.of("REQUEST_BURST"),
                List.of("FAILED_LOGIN_BURST", "REQUEST_BURST"),
                "trusted projection",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 72, "signalProvenance", Map.of("failedLoginBurst", "STORE_DERIVED")));

        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(preProtectablePromotionScorer.score(projection)).thenReturn(assessment);

        hcadFilter.doFilterInternal(request, response, filterChain);

        assertThat(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_SCORE)).isEqualTo(72);
        assertThat(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_BAND)).isEqualTo("REDLINE");
        assertThat(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_ELIGIBLE)).isEqualTo(true);
        assertThat(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_PROVENANCE)).isNotNull();
        assertThat(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATED)).isEqualTo(true);
        verify(pendingAnomalyTriggerOrchestrator).maybeTrigger(eq(request), any());
        assertThat(filterChain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("already evaluated request should not trigger pending anomaly twice")
    void doFilterInternal_alreadyEvaluated_doesNotTriggerAgain() throws Exception {
        setAuthenticated();
        request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATED, true);
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                72,
                HcadPreProtectablePromotionBand.REDLINE,
                true,
                List.of("FAILED_LOGIN_BURST"),
                List.of("REQUEST_BURST"),
                List.of("FAILED_LOGIN_BURST", "REQUEST_BURST"),
                "trusted projection",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 72));

        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(preProtectablePromotionScorer.score(projection)).thenReturn(assessment);

        hcadFilter.doFilterInternal(request, response, filterChain);

        verify(pendingAnomalyTriggerOrchestrator, never()).maybeTrigger(any(), any());
        assertThat(filterChain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("eligible assessment should be recorded when orchestrator is unavailable")
    void doFilterInternal_missingOrchestrator_recordsCandidateWithWriter() throws Exception {
        setAuthenticated();
        hcadFilter = new HCADFilter(
                trustedProjectionFactory,
                preProtectablePromotionScorer,
                hcadProperties,
                () -> null,
                () -> hcadEvaluationWriter);
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                75,
                HcadPreProtectablePromotionBand.REDLINE,
                true,
                List.of("IMPOSSIBLE_TRAVEL"),
                List.of("REQUEST_BURST", "RAPID_SEQUENCE", "PREVIOUS_PATH_JUMP"),
                List.of("IMPOSSIBLE_TRAVEL", "REQUEST_BURST", "RAPID_SEQUENCE", "PREVIOUS_PATH_JUMP"),
                "trusted projection",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 75));
        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(preProtectablePromotionScorer.score(projection)).thenReturn(assessment);
        when(hcadEvaluationWriter.recordCandidate(eq(HcadPreTriggerMode.SHADOW), any())).thenReturn("eval-1");

        hcadFilter.doFilterInternal(request, response, filterChain);

        verify(hcadEvaluationWriter).recordCandidate(eq(HcadPreTriggerMode.SHADOW), any());
        assertThat(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATION_ID)).isEqualTo("eval-1");
        assertThat(filterChain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("shouldNotFilter does not trust browser fetch destinations to bypass HCAD")
    void shouldNotFilter_nonInteractiveFetchDestinations_returnsFalse() {
        request.setRequestURI("/tenant-assets/logo");
        request.addHeader("Sec-Fetch-Dest", "image");
        assertThat(hcadFilter.shouldNotFilter(request)).isFalse();

        request = new MockHttpServletRequest();
        request.setRequestURI("/bundle/runtime");
        request.addHeader("Sec-Fetch-Dest", "script");
        assertThat(hcadFilter.shouldNotFilter(request)).isFalse();

        request = new MockHttpServletRequest();
        request.setRequestURI("/theme/main");
        request.addHeader("Sec-Fetch-Dest", "style");
        assertThat(hcadFilter.shouldNotFilter(request)).isFalse();

        request = new MockHttpServletRequest();
        request.setRequestURI("/font/primary");
        request.addHeader("Sec-Fetch-Dest", "font");
        assertThat(hcadFilter.shouldNotFilter(request)).isFalse();
    }

    @Test
    @DisplayName("shouldNotFilter uses configured excluded patterns for infrastructure paths")
    void shouldNotFilter_configuredInfrastructurePatterns_returnsTrue() {
        hcadProperties.getFilter().getExcludedPatterns().add("/health");
        hcadProperties.getFilter().getExcludedPatterns().add("/actuator/**");

        request.setRequestURI("/health");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();

        request.setRequestURI("/actuator/health");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();

        request.setRequestURI("/actuator/info");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("shouldNotFilter excludes infrastructure paths behind a servlet context path")
    void shouldNotFilter_contextPathInfraPath_returnsTrue() {
        hcadProperties.getFilter().getExcludedPatterns().add("/actuator/**");
        request.setContextPath("/contexa");
        request.setServletPath("/actuator/health");
        request.setRequestURI("/contexa/actuator/health");

        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("shouldNotFilter returns false for API paths")
    void shouldNotFilter_apiPaths_returnsFalse() {
        request.setRequestURI("/api/users");
        request.addHeader("Sec-Fetch-Dest", "empty");
        assertThat(hcadFilter.shouldNotFilter(request)).isFalse();
    }

    @Test
    @DisplayName("shouldNotFilter does not hard-code URL path prefixes")
    void shouldNotFilter_doesNotHardCodeUrlPathPrefixes() {
        request.setRequestURI("/img/logo.png");

        assertThat(hcadFilter.shouldNotFilter(request)).isFalse();
    }

    @Test
    @DisplayName("Unauthenticated request passes through without analysis")
    void doFilterInternal_unauthenticated_passesThrough() throws Exception {
        hcadFilter.doFilterInternal(request, response, filterChain);

        assertThat(filterChain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("Exception during trusted projection results in graceful passthrough")
    void doFilterInternal_exceptionDuringAnalysis_gracefulPassthrough() throws Exception {
        setAuthenticated();
        when(trustedProjectionFactory.project(any(), any()))
                .thenThrow(new RuntimeException("Analysis failed"));

        hcadFilter.doFilterInternal(request, response, filterChain);

        assertThat(filterChain.getRequest()).isNotNull();
        assertThat(request.getAttribute("hcad.analysisStatus")).isEqualTo("FAILED");
        assertThat(request.getAttribute("hcad.failReason")).isEqualTo("RuntimeException");
    }

    @Test
    @DisplayName("Disabled HCAD passes through without analysis")
    void doFilterInternal_disabled_passesThrough() throws Exception {
        hcadProperties.setEnabled(false);
        setAuthenticated();

        hcadFilter.doFilterInternal(request, response, filterChain);

        assertThat(filterChain.getRequest()).isNotNull();
    }

    private TrustedHcadContextProjection projection() {
        return new TrustedHcadContextProjection(
                "testUser",
                "tenant-1",
                "org-1",
                "session-1",
                "ctx-1",
                "GET",
                "/api/test",
                "127.0.0.1",
                "mfa",
                "high",
                true,
                10L,
                "policy-1",
                false,
                false,
                List.of(),
                4,
                12,
                true,
                "/api/previous",
                false,
                0.9,
                true,
                Map.of(),
                Map.of());
    }

    private void setAuthenticated() {
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken("testUser", "password", Collections.emptyList());
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}
