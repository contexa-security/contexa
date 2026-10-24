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
package io.contexa.contexacore.autonomous.handler.handler;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.audit.AgentDecisionRecord;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class AuditingHandler implements SecurityEventHandler {

    private final CentralAuditFacade centralAuditFacade;

    @Override
    public boolean handle(SecurityEventContext context) {
        if (centralAuditFacade == null) {
            return true;
        }

        SecurityEvent event = context.getSecurityEvent();

        try {
            Object resultObj = context.getMetadata().get("processingResult");
            if (!(resultObj instanceof ProcessingResult result)) {
                return true;
            }

            long processingTimeMs = 0;
            SecurityEventContext.ProcessingMetrics metrics = context.getProcessingMetrics();
            if (metrics != null) {
                processingTimeMs = metrics.getResponseTimeMs();
            }

            String action = result.getAction();
            String decision = (action != null && !action.isBlank()) ? action.toUpperCase() : "UNANALYZED";
            String targetResource = getResourceFromMetadata(event);

            Map<String, Object> details = new HashMap<>();
            details.put("eventId", event.getEventId());
            details.put("decision", result.getAction());
            details.put("llmProposedAction", result.getProposedAction());
            details.put("riskScore", result.getRiskScore());
            details.put("confidence", result.getConfidence());
            details.put("llmAuditConfidence", result.resolveAuditConfidence());
            details.put("reasoning", result.getReasoning());
            details.put("technicalFallbackApplied", result.getTechnicalFallbackApplied());
            details.put("technicalFallbackCategory", result.getTechnicalFallbackCategory());
            details.put("technicalFallbackReason", result.getTechnicalFallbackReason());
            details.put("technicalFallbackAction", result.getTechnicalFallbackAction());
            details.put("responseActionFallbackApplied", result.getResponseActionFallbackApplied());
            details.put("responseActionFallbackCategory", result.getResponseActionFallbackCategory());
            details.put("responseActionFallbackReason", result.getResponseActionFallbackReason());
            details.put("responseActionFallbackAction", result.getResponseActionFallbackAction());
            details.put("autonomyConstraintApplied", result.getAutonomyConstraintApplied());
            details.put("autonomyConstraintSummary", result.getAutonomyConstraintSummary());
            details.put("autonomyConstraintReasons", result.getAutonomyConstraintReasons());
            details.put("autonomyConstraintPolicy", result.getAutonomyConstraintPolicy());
            details.put("autonomyConstraintSource", result.getAutonomyConstraintSource());
            details.put("autonomyConstraintVersion", result.getAutonomyConstraintVersion());
            details.put("fieldProvenance", result.getFieldProvenance());
            details.put("severity", event.getSeverity() != null ? event.getSeverity().toString() : null);
            details.put("aiAnalysisLevel", result.getAiAnalysisLevel());
            details.put("processingTimeMs", processingTimeMs);
            details.put("eventSource", event.getSource() != null ? event.getSource().toString() : null);
            details.put("eventTimestamp", event.getTimestamp() != null ? event.getTimestamp().toString() : null);
            if (targetResource != null) {
                details.put("targetResource", targetResource);
            }

            // docs/agent A5-5: the decision record fields (AG-8) and the request's correlation.
            AgentDecisionRecord record = AgentDecisionRecord.of(event, result);
            centralAuditFacade.recordSync(AuditRecord.builder()
                    .correlationId(correlationId(event))
                    .subjectKind(record.subjectKind())
                    .agentId(record.agentId())
                    .delegatorId(record.delegatorId())
                    .delegationId(record.delegationId())
                    .targetAction(record.targetAction())
                    .riskState(record.riskState())
                    .enforcementAction(record.enforcementAction())
                    .enforcementCause(record.enforcementCause())
                    .requestContextHash(record.requestContextHash())
                    .tenantId(metadataText(event, "tenantId"))
                    .eventCategory(AuditEventCategory.SECURITY_DECISION)
                    .principalName(event.getUserId())
                    .eventSource("CORE")
                    .clientIp(event.getSourceIp())
                    .sessionId(event.getSessionId())
                    .userAgent(event.getUserAgent())
                    .resourceIdentifier(targetResource != null ? targetResource : event.getEventId())
                    .resourceUri(targetResource)
                    .action("SECURITY_DECISION")
                    .decision(decision)
                    .reason(result.getReasoning())
                    .outcome(result.isSuccess() ? "COMPLETED" : "FAILED")
                    .riskScore(result.getRiskScore())
                    .details(details)
                    .build());

            return true;

        } catch (Exception e) {
            log.error("[AuditingHandler] Error recording audit log for event: {}", event.getEventId(), e);
            return true;
        }
    }

    /** The request's correlation: its request ID, else its correlation ID, at most the column's 64 characters. */
    private static String correlationId(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        Object value = metadata != null ? metadata.get("requestId") : null;
        if (value == null || value.toString().isBlank()) {
            value = metadata != null ? metadata.get("correlationId") : null;
        }
        if (value == null || value.toString().isBlank()) {
            return null;
        }
        String id = value.toString().trim();
        return id.length() > 64 ? id.substring(0, 64) : id;
    }

    private static String metadataText(SecurityEvent event, String key) {
        Object value = event.getMetadata() != null ? event.getMetadata().get(key) : null;
        return value != null && !value.toString().isBlank() ? value.toString().trim() : null;
    }

    private String getResourceFromMetadata(SecurityEvent event) {
        if (event == null || event.getMetadata() == null) {
            return null;
        }
        Object resource = event.getMetadata().get("targetResource");
        return resource != null ? resource.toString() : null;
    }

    @Override
    public String getName() {
        return "AuditingHandler";
    }

    @Override
    public int getOrder() {
        return 60;
    }
}
