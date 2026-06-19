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

import io.contexa.contexacore.hcad.evaluation.HcadEvaluationWriter;
import io.contexa.contexacore.hcad.trigger.store.AnalysisTriggerStateRepository;
import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PendingAnomalyTriggerOrchestratorTest {

    @Mock
    private PendingAnomalyEligibilityGate eligibilityGate;

    @Mock
    private PendingAnomalyEvidenceCheckService evidenceCheckService;

    @Mock
    private PendingAnomalyEventTriggerService eventTriggerService;

    @Mock
    private AnalysisTriggerStateRepository analysisTriggerStateRepository;

    @Mock
    private HcadEvaluationWriter hcadEvaluationWriter;

    @Test
    @DisplayName("disabled mode should skip HCAD pre-trigger evaluation")
    void maybeTrigger_disabledMode_shouldSkipEvaluation() {
        HcadProperties properties = new HcadProperties();
        properties.getPreTrigger().setMode(HcadPreTriggerMode.DISABLED);
        PendingAnomalyTriggerOrchestrator orchestrator = orchestrator(properties);

        orchestrator.maybeTrigger(new MockHttpServletRequest("GET", "/admin/reports"),
                new UsernamePasswordAuthenticationToken("alice", "n/a", List.of()));

        verifyNoInteractions(eligibilityGate, evidenceCheckService, eventTriggerService, analysisTriggerStateRepository);
    }

    @Test
    @DisplayName("observe mode should evaluate but should not publish an LLM event")
    void maybeTrigger_observeMode_shouldNotPublishLlmEvent() {
        HcadProperties properties = new HcadProperties();
        properties.getPreTrigger().setMode(HcadPreTriggerMode.OBSERVE);
        PendingAnomalyTriggerOrchestrator orchestrator = orchestrator(properties);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/reports");
        PendingAnomalyEligibility eligibility = new PendingAnomalyEligibility("alice", "ctx-1", "base-1");

        when(eligibilityGate.evaluate(eq(request), any())).thenReturn(eligibility);
        when(evidenceCheckService.evaluate(request, eligibility)).thenReturn(triggerReport());

        orchestrator.maybeTrigger(request,
                new UsernamePasswordAuthenticationToken("alice", "n/a", List.of()));

        verify(eventTriggerService, never()).publish(any(), any());
        verify(analysisTriggerStateRepository, never()).tryAcquireInFlight(any(), any());
    }

    @Test
    @DisplayName("shadow mode should publish one HCAD pre-trigger event and mark cooldown")
    void maybeTrigger_shadowMode_shouldPublishEvent() {
        HcadProperties properties = new HcadProperties();
        PendingAnomalyTriggerOrchestrator orchestrator = orchestrator(properties);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/reports");
        PendingAnomalyEligibility eligibility = new PendingAnomalyEligibility("alice", "ctx-1", "base-1");
        PendingAnomalyEvidenceReport report = triggerReport();

        when(eligibilityGate.evaluate(eq(request), any())).thenReturn(eligibility);
        when(evidenceCheckService.evaluate(request, eligibility)).thenReturn(report);
        when(analysisTriggerStateRepository.isCoolingDown("base-1")).thenReturn(false);
        when(analysisTriggerStateRepository.tryAcquireInFlight(eq("base-1"), any(Duration.class))).thenReturn(true);
        when(analysisTriggerStateRepository.tryAcquireRateLimit(eq("global"), any(Duration.class), anyInt())).thenReturn(true);

        orchestrator.maybeTrigger(request,
                new UsernamePasswordAuthenticationToken("alice", "n/a", List.of()));

        verify(eventTriggerService).publish(request, report, null);
        verify(analysisTriggerStateRepository).markCooldown(eq("base-1"), any(Duration.class));
        verify(analysisTriggerStateRepository, never()).releaseInFlight("base-1");
    }

    @Test
    @DisplayName("missing LLM event publisher should still record the HCAD candidate")
    void maybeTrigger_missingPublisher_shouldRecordCandidateOnly() {
        HcadProperties properties = new HcadProperties();
        PendingAnomalyTriggerOrchestrator orchestrator = new PendingAnomalyTriggerOrchestrator(
                eligibilityGate,
                evidenceCheckService,
                null,
                analysisTriggerStateRepository,
                properties,
                hcadEvaluationWriter);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/reports");
        PendingAnomalyEligibility eligibility = new PendingAnomalyEligibility("alice", "ctx-1", "base-1");
        PendingAnomalyEvidenceReport report = triggerReport();

        when(eligibilityGate.evaluate(eq(request), any())).thenReturn(eligibility);
        when(evidenceCheckService.evaluate(request, eligibility)).thenReturn(report);
        when(hcadEvaluationWriter.recordCandidate(HcadPreTriggerMode.SHADOW, report)).thenReturn("eval-no-publisher");

        orchestrator.maybeTrigger(request,
                new UsernamePasswordAuthenticationToken("alice", "n/a", List.of()));

        verify(hcadEvaluationWriter).recordCandidate(HcadPreTriggerMode.SHADOW, report);
        verify(analysisTriggerStateRepository, never()).tryAcquireInFlight(any(), any());
        verify(analysisTriggerStateRepository, never()).tryAcquireRateLimit(any(), any(), anyInt());
    }

    @Test
    @DisplayName("rate-limited trigger should record the candidate but skip LLM publication")
    void maybeTrigger_rateLimited_shouldSkipPublishAndReleaseInflight() {
        HcadProperties properties = new HcadProperties();
        PendingAnomalyTriggerOrchestrator orchestrator = orchestrator(properties, hcadEvaluationWriter);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/reports");
        PendingAnomalyEligibility eligibility = new PendingAnomalyEligibility("alice", "ctx-1", "base-1");
        PendingAnomalyEvidenceReport report = triggerReport();

        when(eligibilityGate.evaluate(eq(request), any())).thenReturn(eligibility);
        when(evidenceCheckService.evaluate(request, eligibility)).thenReturn(report);
        when(hcadEvaluationWriter.recordCandidate(HcadPreTriggerMode.SHADOW, report)).thenReturn("eval-rate");
        when(analysisTriggerStateRepository.isCoolingDown("base-1")).thenReturn(false);
        when(analysisTriggerStateRepository.tryAcquireInFlight(eq("base-1"), any(Duration.class))).thenReturn(true);
        when(analysisTriggerStateRepository.tryAcquireRateLimit(eq("global"), any(Duration.class), anyInt())).thenReturn(false);

        orchestrator.maybeTrigger(request,
                new UsernamePasswordAuthenticationToken("alice", "n/a", List.of()));

        verify(eventTriggerService, never()).publish(any(), any(), any());
        verify(analysisTriggerStateRepository).releaseInFlight("base-1");
        verify(hcadEvaluationWriter, never()).markTriggered("eval-rate");
        verify(hcadEvaluationWriter, never()).markDuplicateSuppressed("eval-rate");
    }

    @Test
    @DisplayName("duplicate trigger should be suppressed and exposed to same-request Protectable suppression")
    void maybeTrigger_duplicate_shouldMarkSuppressedRequestState() {
        HcadProperties properties = new HcadProperties();
        PendingAnomalyTriggerOrchestrator orchestrator = orchestrator(properties, hcadEvaluationWriter);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/reports");
        PendingAnomalyEligibility eligibility = new PendingAnomalyEligibility("alice", "ctx-1", "base-1");
        PendingAnomalyEvidenceReport report = triggerReport();

        when(eligibilityGate.evaluate(eq(request), any())).thenReturn(eligibility);
        when(evidenceCheckService.evaluate(request, eligibility)).thenReturn(report);
        when(hcadEvaluationWriter.recordCandidate(HcadPreTriggerMode.SHADOW, report)).thenReturn("eval-duplicate");
        when(analysisTriggerStateRepository.isCoolingDown("base-1")).thenReturn(true);

        orchestrator.maybeTrigger(request,
                new UsernamePasswordAuthenticationToken("alice", "n/a", List.of()));

        verify(eventTriggerService, never()).publish(any(), any(), any());
        verify(hcadEvaluationWriter).markDuplicateSuppressed("eval-duplicate");
        assertThat(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGERED)).isEqualTo(true);
        assertThat(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_DUPLICATE_SUPPRESSED)).isEqualTo(true);
        assertThat(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_STATE_KEY)).isEqualTo("base-1");
        assertThat(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATION_ID)).isEqualTo("eval-duplicate");
    }

    private PendingAnomalyTriggerOrchestrator orchestrator(HcadProperties properties) {
        return orchestrator(properties, null);
    }

    private PendingAnomalyTriggerOrchestrator orchestrator(HcadProperties properties, HcadEvaluationWriter hcadEvaluationWriter) {
        return new PendingAnomalyTriggerOrchestrator(
                eligibilityGate,
                evidenceCheckService,
                eventTriggerService,
                analysisTriggerStateRepository,
                properties,
                hcadEvaluationWriter);
    }

    private PendingAnomalyEvidenceReport triggerReport() {
        return new PendingAnomalyEvidenceReport(
                true,
                "alice",
                "ctx-1",
                "base-1",
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
                Map.of("promotionScore", 72));
    }
}
