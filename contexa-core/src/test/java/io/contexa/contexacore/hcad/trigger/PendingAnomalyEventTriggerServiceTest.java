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

import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class PendingAnomalyEventTriggerServiceTest {

    @Test
    @DisplayName("shadow mode event carries HCAD shadow boundary metadata")
    void publish_shadowMode_shouldCarryShadowMetadata() {
        ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
        HcadProperties properties = new HcadProperties();
        PendingAnomalyEventTriggerService service = new PendingAnomalyEventTriggerService(publisher, properties);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/reports");

        service.publish(request, triggerReport());

        ArgumentCaptor<Map<String, Object>> payloadCaptor = ArgumentCaptor.forClass(Map.class);
        verify(publisher).publishPreProtectableThreat(eq("alice"), payloadCaptor.capture());
        Map<String, Object> payload = payloadCaptor.getValue();
        assertThat(payload).containsEntry("triggerStage", "PRE_PROTECTABLE");
        assertThat(payload).containsEntry("triggerSource", "HCAD_PRE_TRIGGER");
        assertThat(payload).containsEntry("hcadMode", "SHADOW");
        assertThat(payload).containsEntry("decisionBoundaryMode", "SHADOW");
        assertThat(payload).containsEntry("earlyAnalysisScore", 72);
        assertThat(payload).containsEntry("hcadBand", "REDLINE");

        assertThat(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGERED)).isEqualTo(true);
        assertThat(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_MODE)).isEqualTo("SHADOW");
        assertThat(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_DECISION_BOUNDARY_MODE)).isEqualTo("SHADOW");
        assertThat(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EARLY_ANALYSIS_SCORE)).isEqualTo(72);
        assertThat(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_BAND)).isEqualTo("REDLINE");
    }

    private PendingAnomalyEvidenceReport triggerReport() {
        return new PendingAnomalyEvidenceReport(
                true,
                "alice",
                "ctx-1",
                "state-1",
                "request-1",
                "session-1",
                "/admin/reports",
                "GET",
                "203.0.113.10",
                72,
                "REDLINE",
                true,
                "hcad-promotion-v1",
                List.of("IMPOSSIBLE_TRAVEL"),
                List.of("REQUEST_BURST"),
                List.of("IMPOSSIBLE_TRAVEL", "REQUEST_BURST"),
                "redline candidate",
                "risk-1",
                Map.of("earlyAnalysisScore", 72));
    }
}
