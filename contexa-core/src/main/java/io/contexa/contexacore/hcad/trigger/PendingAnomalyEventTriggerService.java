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
import jakarta.servlet.http.HttpServletRequest;

import java.util.LinkedHashMap;
import java.util.Map;

public class PendingAnomalyEventTriggerService {

    private final ZeroTrustEventPublisher zeroTrustEventPublisher;

    public PendingAnomalyEventTriggerService(ZeroTrustEventPublisher zeroTrustEventPublisher) {
        this.zeroTrustEventPublisher = zeroTrustEventPublisher;
    }

    public void publish(HttpServletRequest request, PendingAnomalyEvidenceReport report) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("triggerStage", "PRE_PROTECTABLE");
        payload.put("triggerSource", "PENDING_REDLINE");
        payload.put("action", ZeroTrustAction.PENDING_ANALYSIS.name());
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

        zeroTrustEventPublisher.publishPreProtectableThreat(report.userId(), payload);

        if (request != null) {
            request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGERED, true);
            request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_STATE_KEY, report.triggerStateKey());
            if (report.requestId() != null) {
                request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_REQUEST_ID, report.requestId());
            }
            if (report.riskSignature() != null) {
                request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_RISK_SIGNATURE, report.riskSignature());
            }
        }
    }
}
