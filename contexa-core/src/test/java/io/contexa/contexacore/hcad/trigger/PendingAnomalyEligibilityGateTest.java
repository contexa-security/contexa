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
package io.contexa.contexacore.hcad.trigger;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAssessment;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionBand;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionRequestProjector;
import io.contexa.contexacore.hcad.trigger.store.AnalysisTriggerStateRepository;
import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PendingAnomalyEligibilityGateTest {

    @Mock
    private ZeroTrustActionRepository actionRepository;

    @Mock
    private AnalysisTriggerStateRepository analysisTriggerStateRepository;

    private PendingAnomalyEligibilityGate eligibilityGate;

    @BeforeEach
    void setUp() {
        eligibilityGate = new PendingAnomalyEligibilityGate(
                actionRepository,
                analysisTriggerStateRepository,
                new HcadProperties());
    }

    @Test
    @DisplayName("pending-analysis users should be eligible when no negative cache is present")
    void evaluate_pendingAnalysis_shouldReturnEligibility() {
        MockHttpServletRequest request = baseRequest("alice", "/api/reports");
        HcadPreProtectablePromotionRequestProjector.project(request, eligibleAssessment(70, List.of("IMPOSSIBLE_TRAVEL", "NEW_DEVICE"), List.of()));

        when(actionRepository.getCurrentAction(eq("alice"), any())).thenReturn(ZeroTrustAction.PENDING_ANALYSIS);
        when(analysisTriggerStateRepository.isNegativeCached(anyString())).thenReturn(false);
        when(analysisTriggerStateRepository.isCoolingDown(anyString())).thenReturn(false);
        when(analysisTriggerStateRepository.isInFlight(anyString())).thenReturn(false);

        PendingAnomalyEligibility eligibility = eligibilityGate.evaluate(
                request,
                new UsernamePasswordAuthenticationToken("alice", "n/a", List.of()));

        assertThat(eligibility).isNotNull();
        assertThat(eligibility.userId()).isEqualTo("alice");
    }

    @Test
    @DisplayName("non-pending users should be ignored by the eligibility gate")
    void evaluate_nonPending_shouldReturnNull() {
        MockHttpServletRequest request = baseRequest("bob", "/api/reports");
        HcadPreProtectablePromotionRequestProjector.project(request, eligibleAssessment(70, List.of("IMPOSSIBLE_TRAVEL"), List.of("REQUEST_BURST")));

        when(actionRepository.getCurrentAction(eq("bob"), any())).thenReturn(ZeroTrustAction.ALLOW);

        PendingAnomalyEligibility eligibility = eligibilityGate.evaluate(
                request,
                new UsernamePasswordAuthenticationToken("bob", "n/a", List.of()));

        assertThat(eligibility).isNull();
    }

    @Test
    @DisplayName("cooling-down pending users should be ignored before anomaly evaluation")
    void evaluate_coolingDown_shouldReturnNull() {
        MockHttpServletRequest request = baseRequest("carol", "/api/reports");
        HcadPreProtectablePromotionRequestProjector.project(request, eligibleAssessment(70, List.of("IMPOSSIBLE_TRAVEL"), List.of("REQUEST_BURST")));
        when(actionRepository.getCurrentAction(eq("carol"), any())).thenReturn(ZeroTrustAction.PENDING_ANALYSIS);
        when(analysisTriggerStateRepository.isNegativeCached(anyString())).thenReturn(false);
        when(analysisTriggerStateRepository.isCoolingDown(anyString())).thenReturn(true);

        PendingAnomalyEligibility eligibility = eligibilityGate.evaluate(
                request,
                new UsernamePasswordAuthenticationToken("carol", "n/a", List.of()));

        assertThat(eligibility).isNull();
    }

    @Test
    @DisplayName("promotion state changes should keep the same dedup key for the same request scope")
    void evaluate_stateChange_shouldKeepSameDedupKey() {
        MockHttpServletRequest first = baseRequest("dave", "/admin/export/reports");
        MockHttpServletRequest second = baseRequest("dave", "/admin/export/reports");
        HcadPreProtectablePromotionRequestProjector.project(first, eligibleAssessment(70, List.of("IMPOSSIBLE_TRAVEL", "NEW_DEVICE"), List.of()));
        HcadPreProtectablePromotionRequestProjector.project(second, eligibleAssessment(80, List.of("IMPOSSIBLE_TRAVEL", "NEW_DEVICE", "FAILED_LOGIN_BURST"), List.of("REQUEST_BURST")));

        when(actionRepository.getCurrentAction(eq("dave"), any())).thenReturn(ZeroTrustAction.PENDING_ANALYSIS);
        when(analysisTriggerStateRepository.isNegativeCached(anyString())).thenReturn(false);
        when(analysisTriggerStateRepository.isCoolingDown(anyString())).thenReturn(false);
        when(analysisTriggerStateRepository.isInFlight(anyString())).thenReturn(false);

        PendingAnomalyEligibility firstEligibility = eligibilityGate.evaluate(
                first,
                new UsernamePasswordAuthenticationToken("dave", "n/a", List.of()));
        PendingAnomalyEligibility secondEligibility = eligibilityGate.evaluate(
                second,
                new UsernamePasswordAuthenticationToken("dave", "n/a", List.of()));

        assertThat(firstEligibility).isNotNull();
        assertThat(secondEligibility).isNotNull();
        assertThat(firstEligibility.baseKey()).isEqualTo(secondEligibility.baseKey());
    }

    private MockHttpServletRequest baseRequest(String userId, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setRequestedSessionId("session-1");
        request.setRemoteAddr("203.0.113.30");
        request.addHeader("User-Agent", "JUnit");
        request.setAttribute("contexa.userId", userId);
        return request;
    }

    private HcadPreProtectablePromotionAssessment eligibleAssessment(int score, List<String> anchors, List<String> corroborators) {
        return new HcadPreProtectablePromotionAssessment(
                score,
                HcadPreProtectablePromotionBand.REDLINE,
                true,
                anchors,
                corroborators,
                anchors,
                "eligible assessment",
                "hcad-promotion-v1",
                Map.of("promotionScore", score));
    }
}
