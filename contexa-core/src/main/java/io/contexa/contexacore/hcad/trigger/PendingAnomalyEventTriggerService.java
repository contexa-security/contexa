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
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.properties.HcadProperties;
import jakarta.servlet.http.HttpServletRequest;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

public class PendingAnomalyEventTriggerService {

    private final Supplier<ZeroTrustEventPublisher> zeroTrustEventPublisherSupplier;
    private final HcadProperties hcadProperties;

    public PendingAnomalyEventTriggerService(ZeroTrustEventPublisher zeroTrustEventPublisher, HcadProperties hcadProperties) {
        this(() -> zeroTrustEventPublisher, hcadProperties);
    }

    public PendingAnomalyEventTriggerService(
            Supplier<ZeroTrustEventPublisher> zeroTrustEventPublisherSupplier,
            HcadProperties hcadProperties) {
        this.zeroTrustEventPublisherSupplier = zeroTrustEventPublisherSupplier;
        this.hcadProperties = hcadProperties;
    }

    public void publish(HttpServletRequest request, PendingAnomalyEvidenceReport report) {
        publish(request, report, null);
    }

    public void publish(HttpServletRequest request, PendingAnomalyEvidenceReport report, String evaluationId) {
        ZeroTrustEventPublisher zeroTrustEventPublisher = zeroTrustEventPublisherSupplier == null
                ? null
                : zeroTrustEventPublisherSupplier.get();
        if (zeroTrustEventPublisher == null) {
            throw new IllegalStateException("No ZeroTrustEventPublisher is configured for HCAD pre-trigger publication.");
        }

        HcadPreTriggerMode mode = hcadProperties.getPreTrigger().effectiveMode();
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("triggerStage", "PRE_PROTECTABLE");
        payload.put("triggerSource", "HCAD_PRE_TRIGGER");
        payload.put("action", ZeroTrustAction.PENDING_ANALYSIS.name());
        payload.put("hcadMode", mode.metadataValue());
        payload.put("decisionBoundaryMode", mode.isShadowBoundary() ? "SHADOW" : mode.metadataValue());
        if (evaluationId != null && !evaluationId.isBlank()) {
            payload.put("hcadEvaluationId", evaluationId);
        }
        payload.put("contextBindingHash", report.contextBindingHash());
        payload.put("triggerStateKey", report.triggerStateKey());
        payload.put("reasonCodes", report.reasonCodes());
        payload.put("reasonSummary", report.reasonSummary());
        payload.put("anchorSignals", report.anchorSignals());
        payload.put("corroboratingSignals", report.corroboratingSignals());
        payload.put("riskSignature", report.riskSignature());
        payload.put("rawSignalSnapshot", report.rawSignalSnapshot());
        payload.put("requestId", report.requestId());
        payload.put("requestPath", report.requestPath());
        payload.put("httpMethod", report.httpMethod());
        payload.put("clientIp", report.clientIp());
        payload.put("hcadEscalationScore", report.escalationScore());
        payload.put("hcadEscalationBand", report.escalationBand());
        payload.put("hcadEscalationEligible", report.escalationEligible());
        payload.put("hcadEscalationReasons", report.reasonCodes());
        payload.put("hcadEscalationSummary", report.reasonSummary());
        payload.put("hcadEscalationVersion", report.escalationVersion());
        payload.put("earlyAnalysisScore", report.escalationScore());
        payload.put("hcadBand", report.escalationBand());

        zeroTrustEventPublisher.publishPreProtectableThreat(report.userId(), payload);

        if (request != null) {
            request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGERED, true);
            request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_STATE_KEY, report.triggerStateKey());
            if (evaluationId != null && !evaluationId.isBlank()) {
                request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATION_ID, evaluationId);
            }
            request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_MODE, mode.metadataValue());
            request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_DECISION_BOUNDARY_MODE,
                    mode.isShadowBoundary() ? "SHADOW" : mode.metadataValue());
            request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EARLY_ANALYSIS_SCORE, report.escalationScore());
            request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_BAND, report.escalationBand());
            if (report.requestId() != null) {
                request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_REQUEST_ID, report.requestId());
            }
            if (report.riskSignature() != null) {
                request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_RISK_SIGNATURE, report.riskSignature());
            }
        }
    }
}
