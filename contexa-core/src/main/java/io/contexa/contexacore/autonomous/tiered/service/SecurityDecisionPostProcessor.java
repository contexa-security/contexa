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
package io.contexa.contexacore.autonomous.tiered.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import java.time.format.DateTimeFormatter;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;


@Slf4j
public class SecurityDecisionPostProcessor {

    private final SecurityContextDataStore dataStore;
    private final UnifiedVectorService unifiedVectorService;

    public SecurityDecisionPostProcessor(
            SecurityContextDataStore dataStore,
            UnifiedVectorService unifiedVectorService) {
        this.dataStore = dataStore;
        this.unifiedVectorService = unifiedVectorService;
    }

    public void updateSessionContext(SecurityEvent event, SecurityDecision decision) {
        String sessionId = event.getSessionId();
        if (sessionId == null || dataStore == null) {
            return;
        }

        try {
            dataStore.addSessionAction(sessionId, buildBehaviorSentence(event, decision));
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    public void storeInVectorDatabase(SecurityEvent event, SecurityDecision decision) {
        if (unifiedVectorService == null) {
            return;
        }

        try {
            ZeroTrustAction action = decision.resolveAutonomousAction();
            if (action == null) {
                log.error("[SecurityDecisionPostProcessor] Decision action is null, skipping vector storage: eventId={}",
                        event.getEventId());
                return;
            }

            switch (action) {
                case ALLOW -> storeBehaviorDocument(event, decision);
                case BLOCK -> storeThreatDocument(event, decision);
                case CHALLENGE -> storeSuspiciousDocument(event, decision);
                case ESCALATE, PENDING_ANALYSIS -> storeAmbiguousDocument(event, decision);
            }

        } catch (Exception e) {
            log.error("[SecurityDecisionPostProcessor] Failed to store vector document: eventId={}",
                    event.getEventId(), e);
        }
    }

    private void storeBehaviorDocument(SecurityEvent event, SecurityDecision decision) {
        try {
            String content = buildBehaviorContent(event, decision);
            Map<String, Object> metadata = buildEnrichedMetadata(event, decision, VectorDocumentType.BEHAVIOR.getValue());

            Document document = new Document(content, metadata);
            unifiedVectorService.storeDocument(document);
        } catch (Exception e) {
            log.error("[SecurityDecisionPostProcessor] Failed to store behavior document: eventId={}",
                    event.getEventId(), e);
        }
    }

    private String buildBehaviorSentence(SecurityEvent event, SecurityDecision decision) {
        StringBuilder sentence = new StringBuilder();

        String method = null;
        String path = extractPath(event);
        if (event.getMetadata() != null) {
            Object m = event.getMetadata().get("httpMethod");
            if (m != null) method = m.toString();
        }

        sentence.append("User accessed ");
        if (path != null) {
            sentence.append(path);
        } else if (event.getDescription() != null) {
            sentence.append(event.getDescription());
        }
        if (method != null) {
            sentence.append(" via ").append(method);
        }
        if (event.getSourceIp() != null) {
            sentence.append(" from ").append(event.getSourceIp());
        }

        String browser = SecurityEventEnricher.extractBrowserSignature(event.getUserAgent());
        String os = SecurityEventEnricher.extractOSFromUserAgent(event.getUserAgent());
        if (browser != null) {
            sentence.append(" using ").append(browser);
        }
        if (os != null) {
            sentence.append(" on ").append(os);
        }

        if (event.getTimestamp() != null) {
            sentence.append(String.format(" at %02d:%02d",
                    event.getTimestamp().getHour(),
                    event.getTimestamp().getMinute()));
        }

        ZeroTrustAction observedAction = decision.resolveAutonomousAction();
        if (observedAction != null) {
            sentence.append(", observed ").append(observedAction.name().toLowerCase());
        }

        return sentence.toString();
    }

    private String buildBehaviorContent(SecurityEvent event, SecurityDecision decision) {
        StringBuilder sb = new StringBuilder();
        Double effectiveRiskScore = resolveEffectiveRiskScore(decision);
        Double effectiveConfidence = resolveEffectiveConfidence(decision);
        Double auditRiskScore = decision.resolveAuditRiskScore();
        Double auditConfidence = decision.resolveAuditConfidence();

        sb.append(buildActionSummary(event, decision));
        sb.append("\n");

        sb.append("Decision: proposedAction=").append(decision.getAction() != null ? decision.getAction().name() : "UNKNOWN");
        ZeroTrustAction autonomousAction = decision.resolveAutonomousAction();
        if (autonomousAction != null) {
            sb.append(", autonomousAction=").append(autonomousAction.name());
        }
        sb.append(", riskScore=").append(formatScore(effectiveRiskScore));
        sb.append(", confidence=").append(formatScore(effectiveConfidence));
        if (auditRiskScore != null) {
            sb.append(", llmAuditRiskScore=").append(formatScore(auditRiskScore));
        }
        if (auditConfidence != null) {
            sb.append(", llmAuditConfidence=").append(formatScore(auditConfidence));
        }
        if (decision.getProcessingLayer() > 0) {
            sb.append(", analysisLayer=").append(decision.getProcessingLayer());
        }
        sb.append("\n");

        if (decision.getReasoning() != null && !decision.getReasoning().isBlank()) {
            sb.append("Reasoning: ").append(truncate(decision.getReasoning(), 300)).append("\n");
        }
        if (Boolean.TRUE.equals(decision.getAutonomyConstraintApplied())) {
            sb.append("AutonomyConstraint: ")
                    .append(truncate(decision.getAutonomyConstraintSummary(), 220))
                    .append("\n");
        }
        appendSessionContext(sb, event);

        return sb.toString();
    }

    private void storeThreatDocument(SecurityEvent event, SecurityDecision decision) {
        try {
            String content = buildThreatContent(event, decision);
            Map<String, Object> metadata = buildEnrichedMetadata(event, decision, VectorDocumentType.THREAT.getValue());

            if (decision.getBehaviorPatterns() != null && !decision.getBehaviorPatterns().isEmpty()) {
                metadata.put("behaviorPatterns", String.join(", ", decision.getBehaviorPatterns()));
            }

            Document threatDoc = new Document(content, metadata);
            unifiedVectorService.storeDocument(threatDoc);
        } catch (Exception e) {
            log.error("[SecurityDecisionPostProcessor] Failed to store threat document: eventId={}",
                    event.getEventId(), e);
        }
    }

    private String buildThreatContent(SecurityEvent event, SecurityDecision decision) {
        StringBuilder sb = new StringBuilder();

        sb.append(buildActionSummary(event, decision));
        sb.append("\n");

        if (decision.getThreatCategory() != null) {
            sb.append("ThreatCategory: ").append(decision.getThreatCategory()).append("\n");
        }

        if (decision.getBehaviorPatterns() != null && !decision.getBehaviorPatterns().isEmpty()) {
            sb.append("BehaviorPatterns: ").append(String.join(", ", decision.getBehaviorPatterns())).append("\n");
        }

        appendSessionContext(sb, event);

        return sb.toString();
    }

    private void storeSuspiciousDocument(SecurityEvent event, SecurityDecision decision) {
        try {
            String content = buildSuspiciousContent(event, decision);
            Map<String, Object> metadata = buildEnrichedMetadata(event, decision, VectorDocumentType.SUSPICIOUS.getValue());

            Document doc = new Document(content, metadata);
            unifiedVectorService.storeDocument(doc);
        } catch (Exception e) {
            log.error("[SecurityDecisionPostProcessor] Failed to store suspicious document: eventId={}",
                    event.getEventId(), e);
        }
    }

    private String buildSuspiciousContent(SecurityEvent event, SecurityDecision decision) {
        StringBuilder sb = new StringBuilder();

        sb.append(buildActionSummary(event, decision));
        sb.append("\n");

        appendSessionContext(sb, event);

        return sb.toString();
    }

    private void storeAmbiguousDocument(SecurityEvent event, SecurityDecision decision) {
        try {
            String content = buildAmbiguousContent(event, decision);
            Map<String, Object> metadata = buildEnrichedMetadata(event, decision, VectorDocumentType.AMBIGUOUS.getValue());

            Document doc = new Document(content, metadata);
            unifiedVectorService.storeDocument(doc);
        } catch (Exception e) {
            log.error("[SecurityDecisionPostProcessor] Failed to store ambiguous document: eventId={}",
                    event.getEventId(), e);
        }
    }

    private String buildAmbiguousContent(SecurityEvent event, SecurityDecision decision) {
        StringBuilder sb = new StringBuilder();

        sb.append(buildActionSummary(event, decision));
        sb.append("\n");

        appendSessionContext(sb, event);

        return sb.toString();
    }

    private String buildActionSummary(SecurityEvent event, SecurityDecision decision) {
        StringBuilder sentence = new StringBuilder();

        String method = extractMetaString(event, "httpMethod");
        String path = extractPath(event);

        sentence.append("User accessed ");
        if (path != null) {
            sentence.append(path);
        } else if (event.getDescription() != null) {
            sentence.append(event.getDescription());
        }
        if (method != null) {
            sentence.append(" via ").append(method);
        }
        if (event.getSourceIp() != null) {
            sentence.append(" from ").append(event.getSourceIp());
        }

        String browser = SecurityEventEnricher.extractBrowserSignature(event.getUserAgent());
        String os = SecurityEventEnricher.extractOSFromUserAgent(event.getUserAgent());
        if (browser != null) {
            sentence.append(" using ").append(browser);
        }
        if (os != null) {
            sentence.append(" on ").append(os);
        }

        if (event.getTimestamp() != null) {
            sentence.append(String.format(" at %02d:%02d",
                    event.getTimestamp().getHour(),
                    event.getTimestamp().getMinute()));
            int dow = event.getTimestamp().getDayOfWeek().getValue();
            sentence.append(" (").append(dayOfWeekLabel(dow)).append(")");
        }

        return sentence.toString();
    }

    private void appendSessionContext(StringBuilder sb, SecurityEvent event) {
        if (event.getMetadata() == null) return;

        Object mfaVerified = event.getMetadata().get("mfaVerified");
        if (mfaVerified != null) {
            sb.append("MfaVerified: ").append(mfaVerified).append("\n");
        }

        Object isNewDevice = event.getMetadata().get("isNewDevice");
        if (Boolean.TRUE.equals(isNewDevice)) {
            sb.append("NewDevice: true\n");
        }

        Object isNewSession = event.getMetadata().get("isNewSession");
        if (Boolean.TRUE.equals(isNewSession)) {
            sb.append("NewSession: true\n");
        }

        Object recentRequestCount = event.getMetadata().get("recentRequestCount");
        if (recentRequestCount instanceof Number) {
            sb.append("RecentRequestCount: ").append(recentRequestCount).append("\n");
        }

        Object failedLoginAttempts = event.getMetadata().get("failedLoginAttempts");
        if (failedLoginAttempts == null) {
            failedLoginAttempts = event.getMetadata().get("auth.failure_count");
        }
        if (failedLoginAttempts instanceof Number && ((Number) failedLoginAttempts).intValue() > 0) {
            sb.append("FailedLoginAttempts: ").append(failedLoginAttempts).append("\n");
        }

        Object isSensitive = event.getMetadata().get("isSensitiveResource");
        if (Boolean.TRUE.equals(isSensitive)) {
            sb.append("SensitiveResource: true\n");
        }
    }

    private Map<String, Object> buildEnrichedMetadata(SecurityEvent event, SecurityDecision decision, String documentType) {
        Map<String, Object> metadata = new HashMap<>();

        metadata.put("documentType", documentType);

        metadata.put(VectorDocumentMetadata.SOURCE_TYPE, documentType);
        metadata.put(VectorDocumentMetadata.ACCESS_SCOPE, event.getUserId() != null ? "USER" : "GLOBAL");
        metadata.put(VectorDocumentMetadata.ARTIFACT_ID, event.getEventId() != null ? event.getEventId() : UUID.randomUUID().toString());
        metadata.put(VectorDocumentMetadata.ARTIFACT_VERSION, "1.0");
        metadata.put(VectorDocumentMetadata.RETRIEVAL_PURPOSE, "security_investigation");
        metadata.put(VectorDocumentMetadata.PROVENANCE_SUMMARY, "Security decision memory from runtime event");

        String eventTimestamp = event.getTimestamp() != null
                ? event.getTimestamp().toString()
                : LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        metadata.put("timestamp", eventTimestamp);

        if (event.getTimestamp() != null) {
            metadata.put("hour", event.getTimestamp().getHour());
            metadata.put("dayOfWeek", event.getTimestamp().getDayOfWeek().getValue());
        }

        if (event.getEventId() != null) {
            metadata.put("eventId", event.getEventId());
        }
        if (event.getUserId() != null) {
            metadata.put("userId", event.getUserId());
            String organizationId = resolveOrganizationId(event);
            if (organizationId != null) {
                metadata.put(VectorDocumentMetadata.ORGANIZATION_ID, organizationId);
            }
        }
        if (event.getSourceIp() != null) {
            metadata.put("sourceIp", event.getSourceIp());
        }
        if (event.getSessionId() != null) {
            metadata.put("sessionId", event.getSessionId());
        }

        if (decision.getAction() != null) {
            metadata.put("proposedAction", decision.getAction().name());
        }
        ZeroTrustAction autonomousAction = decision.resolveAutonomousAction();
        if (autonomousAction != null) {
            metadata.put("action", autonomousAction.name());
            metadata.put("autonomousAction", autonomousAction.name());
        }
        Double effectiveRiskScore = resolveEffectiveRiskScore(decision);
        Double auditRiskScore = decision.resolveAuditRiskScore();
        metadata.put("riskScore", sanitizeScore(effectiveRiskScore != null ? effectiveRiskScore : auditRiskScore));
        if (auditRiskScore != null) {
            metadata.put("llmAuditRiskScore", sanitizeScore(auditRiskScore));
        }

        Double effectiveConfidence = resolveEffectiveConfidence(decision);
        Double auditConfidence = decision.resolveAuditConfidence();
        metadata.put("confidence", sanitizeScore(effectiveConfidence != null ? effectiveConfidence : auditConfidence));
        if (auditConfidence != null) {
            metadata.put("llmAuditConfidence", sanitizeScore(auditConfidence));
        }
        if (decision.getTechnicalFallbackApplied() != null) {
            metadata.put("technicalFallbackApplied", decision.getTechnicalFallbackApplied());
        }
        putIfNotBlank(metadata, "technicalFallbackCategory", decision.getTechnicalFallbackCategory());
        putIfNotBlank(metadata, "technicalFallbackReason", decision.getTechnicalFallbackReason());
        putIfNotBlank(metadata, "technicalFallbackAction", decision.getTechnicalFallbackAction());
        if (decision.getResponseActionFallbackApplied() != null) {
            metadata.put("responseActionFallbackApplied", decision.getResponseActionFallbackApplied());
        }
        putIfNotBlank(metadata, "responseActionFallbackCategory", decision.getResponseActionFallbackCategory());
        putIfNotBlank(metadata, "responseActionFallbackReason", decision.getResponseActionFallbackReason());
        putIfNotBlank(metadata, "responseActionFallbackAction", decision.getResponseActionFallbackAction());
        if (decision.getFieldProvenance() != null && !decision.getFieldProvenance().isEmpty()) {
            metadata.put("fieldProvenance", Map.copyOf(decision.getFieldProvenance()));
        }
        if (Boolean.TRUE.equals(decision.getAutonomyConstraintApplied())) {
            metadata.put("autonomyConstraintApplied", true);
            if (decision.getAutonomyConstraintSummary() != null) {
                metadata.put("autonomyConstraintSummary", decision.getAutonomyConstraintSummary());
            }
            if (decision.getAutonomyConstraintReasons() != null && !decision.getAutonomyConstraintReasons().isEmpty()) {
                metadata.put("autonomyConstraintReasons", decision.getAutonomyConstraintReasons());
            }
            putIfNotBlank(metadata, "autonomyConstraintPolicy", decision.getAutonomyConstraintPolicy());
            putIfNotBlank(metadata, "autonomyConstraintSource", decision.getAutonomyConstraintSource());
            putIfNotBlank(metadata, "autonomyConstraintVersion", decision.getAutonomyConstraintVersion());
        }
        if (decision.getProcessingLayer() > 0) {
            metadata.put("analysisDepth", decision.getProcessingLayer());
        }

        if (decision.getThreatCategory() != null) {
            metadata.put("threatCategory", decision.getThreatCategory());
        }

        String requestPath = extractPath(event);
        if (requestPath != null) {
            metadata.put("requestPath", requestPath);
            String pathFamily = SecuritySemanticNormalizer.normalizePathFamily(requestPath);
            if (pathFamily != null) {
                metadata.put("pathFamily", pathFamily);
            }
        }

        String httpMethod = extractMetaString(event, "httpMethod");
        if (httpMethod != null) {
            metadata.put("httpMethod", httpMethod);
            String normalizedActionFamily = SecuritySemanticNormalizer.normalizeActionFamily(
                    extractMetaString(event, "actionFamily"),
                    httpMethod,
                    metadata.get("action"),
                    metadata.get("proposedAction"));
            if (normalizedActionFamily != null) {
                metadata.put("actionFamily", normalizedActionFamily);
            }
        }

        if (event.getUserAgent() != null && !event.getUserAgent().isEmpty()) {
            metadata.put("userAgent", event.getUserAgent());
            String userAgentOS = SecurityEventEnricher.extractOSFromUserAgent(event.getUserAgent());
            if (userAgentOS != null) {
                metadata.put("userAgentOS", userAgentOS);
            }

            String browser = SecurityEventEnricher.extractBrowserSignature(event.getUserAgent());
            if (browser != null) {
                metadata.put("userAgentBrowser", browser);
            }
        }

        Map<String, Object> eventMeta = event.getMetadata();
        if (eventMeta != null) {
            copyIfPresent(eventMeta, metadata, "tenantId");
            copyIfPresent(eventMeta, metadata, "tenant_id");
            copyIfPresent(eventMeta, metadata, "organizationId");
            copyIfPresent(eventMeta, metadata, "organization_id");
            copyIfPresent(eventMeta, metadata, "orgId");
            copyIfPresent(eventMeta, metadata, "resourceId");
            copyIfPresent(eventMeta, metadata, "resourceType");
            copyIfPresent(eventMeta, metadata, "resourceCategory");
            copyIfPresent(eventMeta, metadata, "resourceSensitivity");
            copyIfPresent(eventMeta, metadata, "resourceBusinessLabel");
            copyIfPresent(eventMeta, metadata, "resourceLabel");
            copyIfPresent(eventMeta, metadata, "businessLabel");
            copyIfPresent(eventMeta, metadata, "authenticationType");
            copyIfPresent(eventMeta, metadata, "mfaVerified");
            copyIfPresent(eventMeta, metadata, "currentAccessHour");
            copyIfPresent(eventMeta, metadata, "concurrentSessions");
            copyIfPresent(eventMeta, metadata, "passwordAgeDays");
            copyIfPresent(eventMeta, metadata, "sessionAgeMinutes");
            copyIfPresent(eventMeta, metadata, "country");
            copyIfPresent(eventMeta, metadata, "city");
            copyIfPresent(eventMeta, metadata, "ipBand");
            copyIfPresent(eventMeta, metadata, "asn");
            copyIfPresent(eventMeta, metadata, "deviceOs");
            copyIfPresent(eventMeta, metadata, "deviceOsVersion");
            copyIfPresent(eventMeta, metadata, "deviceBrowser");
            copyIfPresent(eventMeta, metadata, "deviceBrowserVersion");
            copyIfPresent(eventMeta, metadata, "deviceScreenResolution");
            copyIfPresent(eventMeta, metadata, "deviceLanguage");
            copyIfPresent(eventMeta, metadata, "deviceFingerprintMatch");
            copyIfPresent(eventMeta, metadata, "intentBotUserAgent");
            copyIfPresent(eventMeta, metadata, "intentMissingReferer");
            copyIfPresent(eventMeta, metadata, "intentLanguageMismatch");
            copyIfPresent(eventMeta, metadata, "intentTlsFingerprintAltered");
            copyIfPresent(eventMeta, metadata, "intentAbnormalHeaderOrder");
            copyIfPresent(eventMeta, metadata, "isSensitiveResource");
            copyIfPresent(eventMeta, metadata, "geoCountry");
            copyIfPresent(eventMeta, metadata, "geoCity");
            copyIfPresent(eventMeta, metadata, "geoLatitude");
            copyIfPresent(eventMeta, metadata, "geoLongitude");
            if (Boolean.TRUE.equals(eventMeta.get("impossibleTravel"))) {
                metadata.put("impossibleTravel", true);
                copyIfPresent(eventMeta, metadata, "travelDistanceKm");
                copyIfPresent(eventMeta, metadata, "travelElapsedMinutes");
                copyIfPresent(eventMeta, metadata, "previousLocation");
            }
        }

        String normalizedAuthenticationType = SecuritySemanticNormalizer.normalizeAuthenticationType(
                metadata.get("authenticationType"),
                eventMeta != null ? eventMeta.get("authMethod") : null);
        if (normalizedAuthenticationType != null) {
            metadata.put("authenticationType", normalizedAuthenticationType);
        }
        String normalizedResourceFamily = SecuritySemanticNormalizer.normalizeResourceFamily(
                metadata.get("resourceFamily"),
                metadata.get("resourceType"),
                metadata.get("resourceCategory"),
                metadata.get("resourceSensitivity"));
        if (normalizedResourceFamily != null) {
            metadata.put("resourceFamily", normalizedResourceFamily);
        }
        String normalizedNetwork = SecuritySemanticNormalizer.normalizeNetwork(
                textValue(metadata.get("sourceIp")),
                textValue(metadata.get("ipBand")));
        if (normalizedNetwork != null) {
            metadata.put("ipBand", normalizedNetwork);
        }

        return metadata;
    }

    private String extractPath(SecurityEvent event) {
        if (event.getMetadata() != null) {
            Object uri = event.getMetadata().get("requestPath");
            if (uri != null) {
                return uri.toString();
            }

            Object fullPath = event.getMetadata().get("fullPath");
            if (fullPath != null) {
                return fullPath.toString();
            }
        }
        return null;
    }

    private String extractMetaString(SecurityEvent event, String key) {
        if (event.getMetadata() == null) return null;
        Object val = event.getMetadata().get(key);
        return val != null ? val.toString() : null;
    }

    private static void copyIfPresent(Map<String, Object> source, Map<String, Object> target, String key) {
        Object val = source.get(key);
        if (val != null) {
            target.put(key, val);
        }
    }

    private static String formatScore(Double score) {
        if (score == null || Double.isNaN(score)) return "N/A";
        return String.format("%.2f", score);
    }

    private static String resolveOrganizationId(SecurityEvent event) {
        if (event == null) {
            return null;
        }
        Map<String, Object> eventMeta = event.getMetadata();
        if (eventMeta != null) {
            String metadataOrganizationId = firstNonBlankText(
                    textValue(eventMeta.get(VectorDocumentMetadata.ORGANIZATION_ID)),
                    textValue(eventMeta.get("organizationId")),
                    textValue(eventMeta.get("tenantId")),
                    textValue(eventMeta.get("orgId")));
            if (metadataOrganizationId != null) {
                return metadataOrganizationId;
            }
        }
        return null;
    }

    private static String textValue(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }

    private static String firstNonBlankText(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private static Double resolveEffectiveRiskScore(SecurityDecision decision) {
        if (decision == null) {
            return null;
        }
        return decision.getRiskScore() != null ? decision.getRiskScore() : decision.resolveAuditRiskScore();
    }

    private static Double resolveEffectiveConfidence(SecurityDecision decision) {
        if (decision == null) {
            return null;
        }
        return decision.getConfidence() != null ? decision.getConfidence() : decision.resolveAuditConfidence();
    }

    private static double sanitizeScore(Double score) {
        if (score == null || Double.isNaN(score)) {
            return -1.0;
        }
        return score;
    }

    private static void putIfNotBlank(Map<String, Object> target, String key, String value) {
        if (value != null && !value.isBlank()) {
            target.put(key, value);
        }
    }

    private static String formatScore(double score) {
        if (Double.isNaN(score)) return "N/A";
        return String.format("%.2f", score);
    }

    private static String truncate(String text, int maxLen) {
        if (text == null) return "";
        return text.length() > maxLen ? text.substring(0, maxLen) + "..." : text;
    }

    private static String dayOfWeekLabel(int dow) {
        return switch (dow) {
            case 1 -> "Mon";
            case 2 -> "Tue";
            case 3 -> "Wed";
            case 4 -> "Thu";
            case 5 -> "Fri";
            case 6 -> "Sat";
            case 7 -> "Sun";
            default -> "?";
        };
    }
}
