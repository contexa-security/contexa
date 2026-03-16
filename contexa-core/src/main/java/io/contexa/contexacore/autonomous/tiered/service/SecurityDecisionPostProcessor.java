package io.contexa.contexacore.autonomous.tiered.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
            if (decision.getAction() == ZeroTrustAction.BLOCK) {
                dataStore.setSessionRisk(sessionId, decision.getRiskScore());
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    public void storeInVectorDatabase(SecurityEvent event, SecurityDecision decision) {
        if (unifiedVectorService == null) {
            return;
        }

        try {
            ZeroTrustAction action = decision.getAction();
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

    // ── ALLOW: behavior document ──

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

    private String buildBehaviorContent(SecurityEvent event, SecurityDecision decision) {
        StringBuilder sb = new StringBuilder();

        sb.append(buildActionSummary(event, decision));
        sb.append("\n");

        sb.append("Decision: action=").append(decision.getAction().name());
        sb.append(", riskScore=").append(formatScore(decision.getRiskScore()));
        sb.append(", confidence=").append(formatScore(decision.getConfidence()));
        if (decision.getProcessingLayer() > 0) {
            sb.append(", analysisLayer=").append(decision.getProcessingLayer());
        }
        sb.append("\n");

        if (decision.getReasoning() != null && !decision.getReasoning().isBlank()) {
            sb.append("Reasoning: ").append(truncate(decision.getReasoning(), 300)).append("\n");
        }

        appendSessionContext(sb, event);

        return sb.toString();
    }

    // ── BLOCK: threat document ──

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

        sb.append("[BLOCKED] ");
        sb.append(buildActionSummary(event, decision));
        sb.append("\n");

        sb.append("Threat: action=BLOCK");
        sb.append(", riskScore=").append(formatScore(decision.getRiskScore()));
        sb.append(", confidence=").append(formatScore(decision.getConfidence()));
        if (decision.getProcessingLayer() > 0) {
            sb.append(", analysisLayer=").append(decision.getProcessingLayer());
        }
        sb.append("\n");

        if (decision.getThreatCategory() != null) {
            sb.append("ThreatCategory: ").append(decision.getThreatCategory()).append("\n");
        }

        if (decision.getBehaviorPatterns() != null && !decision.getBehaviorPatterns().isEmpty()) {
            sb.append("BehaviorPatterns: ").append(String.join(", ", decision.getBehaviorPatterns())).append("\n");
        }

        if (decision.getReasoning() != null && !decision.getReasoning().isBlank()) {
            sb.append("Reasoning: ").append(truncate(decision.getReasoning(), 500)).append("\n");
        }

        if (decision.getEvidence() != null && !decision.getEvidence().isEmpty()) {
            sb.append("Evidence: ").append(String.join("; ", decision.getEvidence())).append("\n");
        }

        appendSessionContext(sb, event);

        return sb.toString();
    }

    // ── CHALLENGE: suspicious document ──

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

        sb.append("[CHALLENGED] ");
        sb.append(buildActionSummary(event, decision));
        sb.append("\n");

        sb.append("Decision: action=CHALLENGE");
        sb.append(", riskScore=").append(formatScore(decision.getRiskScore()));
        sb.append(", confidence=").append(formatScore(decision.getConfidence()));
        if (decision.getProcessingLayer() > 0) {
            sb.append(", analysisLayer=").append(decision.getProcessingLayer());
        }
        sb.append("\n");

        if (decision.getReasoning() != null && !decision.getReasoning().isBlank()) {
            sb.append("Reasoning: ").append(truncate(decision.getReasoning(), 400)).append("\n");
        }

        appendSessionContext(sb, event);

        return sb.toString();
    }

    // ── ESCALATE/PENDING: ambiguous document ──

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

        sb.append("[ESCALATED] ");
        sb.append(buildActionSummary(event, decision));
        sb.append("\n");

        sb.append("Decision: action=").append(decision.getAction().name());
        sb.append(", riskScore=").append(formatScore(decision.getRiskScore()));
        sb.append(", confidence=").append(formatScore(decision.getConfidence()));
        sb.append("\n");

        if (decision.getReasoning() != null && !decision.getReasoning().isBlank()) {
            sb.append("Reasoning: ").append(truncate(decision.getReasoning(), 400)).append("\n");
        }

        appendSessionContext(sb, event);

        return sb.toString();
    }

    // ── shared builders ──

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
        }
        if (event.getSourceIp() != null) {
            metadata.put("sourceIp", event.getSourceIp());
        }
        if (event.getSessionId() != null) {
            metadata.put("sessionId", event.getSessionId());
        }

        if (decision.getAction() != null) {
            metadata.put("action", decision.getAction().name());
        }
        double rs = decision.getRiskScore();
        metadata.put("riskScore", Double.isNaN(rs) ? -1.0 : rs);
        double conf = decision.getConfidence();
        metadata.put("confidence", Double.isNaN(conf) ? -1.0 : conf);

        if (decision.getProcessingLayer() > 0) {
            metadata.put("analysisDepth", decision.getProcessingLayer());
        }

        if (decision.getThreatCategory() != null) {
            metadata.put("threatCategory", decision.getThreatCategory());
        }

        String requestPath = extractPath(event);
        if (requestPath != null) {
            metadata.put("requestPath", requestPath);
        }

        String httpMethod = extractMetaString(event, "httpMethod");
        if (httpMethod != null) {
            metadata.put("httpMethod", httpMethod);
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
