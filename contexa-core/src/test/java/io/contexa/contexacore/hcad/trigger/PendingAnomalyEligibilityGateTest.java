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
import io.contexa.contexacore.hcad.trigger.store.InMemoryAnalysisTriggerStateRepository;
import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PendingAnomalyEligibilityGateTest {

    @Test
    @DisplayName("low-risk negative cache should suppress eligibility until TTL expires")
    void evaluate_negativeCacheSuppressesEligibilityUntilTtlExpires() throws Exception {
        ZeroTrustActionRepository actionRepository = mock(ZeroTrustActionRepository.class);
        when(actionRepository.getCurrentAction(anyString(), anyString())).thenReturn(ZeroTrustAction.ALLOW);
        InMemoryAnalysisTriggerStateRepository stateRepository = new InMemoryAnalysisTriggerStateRepository();
        PendingAnomalyEligibilityGate gate = new PendingAnomalyEligibilityGate(
                actionRepository,
                stateRepository,
                new HcadProperties());
        MockHttpServletRequest request = request();
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken("alice", "n/a", List.of());
        projectLowRiskAssessment(request);

        PendingAnomalyEligibility first = gate.evaluate(request, authentication);
        stateRepository.markNegative(first.baseKey(), Duration.ofMillis(50));
        PendingAnomalyEligibility cached = gate.evaluate(request, authentication);
        Thread.sleep(100L);
        PendingAnomalyEligibility afterTtl = gate.evaluate(request, authentication);

        assertThat(first).isNotNull();
        assertThat(first.actorSessionKey()).isEqualTo("actor-1");
        assertThat(cached).isNull();
        assertThat(afterTtl).isNotNull();
        assertThat(afterTtl.actorSessionKey()).isEqualTo("actor-1");
    }

    private MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/dashboard");
        request.setRequestURI("/admin/dashboard");
        request.setServletPath("/admin/dashboard");
        request.setRequestedSessionId("session-1");
        request.setRemoteAddr("203.0.113.10");
        request.addHeader("User-Agent", "JUnit");
        return request;
    }

    private void projectLowRiskAssessment(MockHttpServletRequest request) {
        HcadPreProtectablePromotionRequestProjector.project(
                request,
                new HcadPreProtectablePromotionAssessment(
                        10,
                        HcadPreProtectablePromotionBand.LOW,
                        false,
                        List.of(),
                        List.of("PREVIOUS_PATH_JUMP"),
                        List.of("PREVIOUS_PATH_JUMP"),
                        "low-risk window",
                        "hcad-promotion-v2-trusted-projection",
                        Map.of(
                                "userId", "alice",
                                "actorSessionKey", "actor-1",
                                "earlyAnalysisScore", 10)));
    }
}
