package io.contexa.contexacore.autonomous.tiered.service;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class SecurityDecisionPostProcessor {

    private final RedisTemplate<String, Object> redisTemplate;
    private final UnifiedVectorService unifiedVectorService;

    public SecurityDecisionPostProcessor(
            RedisTemplate<String, Object> redisTemplate,
            UnifiedVectorService unifiedVectorService) {
        this.redisTemplate = redisTemplate;
        this.unifiedVectorService = unifiedVectorService;
    }

    public void updateSessionContext(SecurityEvent event, SecurityDecision decision) {
        String sessionId = event.getSessionId();
        if (sessionId == null || redisTemplate == null) {
            return;
        }

        try {

            String sessionActionsKey = ZeroTrustRedisKeys.sessionActions(sessionId);
            redisTemplate.opsForList().rightPush(
                    sessionActionsKey,
                    String.format("%s:%s",
                            event.getDescription() != null ? event.getDescription() : "action",
                            decision.getAction())
            );

            redisTemplate.expire(sessionActionsKey, Duration.ofHours(24));

            Long size = redisTemplate.opsForList().size(sessionActionsKey);
            if (size != null && size > 100) {
                redisTemplate.opsForList().leftPop(sessionActionsKey);
            }

            SecurityDecision.Action sessionAction = decision.getAction();
            if (sessionAction == SecurityDecision.Action.BLOCK) {
                redisTemplate.opsForValue().set(
                        ZeroTrustRedisKeys.sessionRisk(sessionId),
                        decision.getRiskScore(),
                        Duration.ofHours(1)
                );
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
            SecurityDecision.Action action = decision.getAction();

            double confidence = decision.getConfidence();
            if (Double.isNaN(confidence)) {

            }

            if (action == SecurityDecision.Action.ALLOW) {
                storeBehaviorDocument(event, decision);
            }

            if (action == SecurityDecision.Action.BLOCK) {
                storeBehaviorDocument(event, decision);
                String content = buildBehaviorContent(event, decision);
                storeThreatDocument(event, decision, content);
            }

        } catch (Exception e) {
        }
    }

    private void storeBehaviorDocument(SecurityEvent event, SecurityDecision decision) {
        try {
            String content = buildBehaviorContent(event, decision);
            Map<String, Object> metadata = buildBaseMetadata(event, decision, VectorDocumentType.BEHAVIOR.getValue());

            Document document = new Document(content, metadata);
            unifiedVectorService.storeDocument(document);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    private String buildBehaviorContent(SecurityEvent event, SecurityDecision decision) {
        StringBuilder content = new StringBuilder();

        if (event.getUserId() != null) {
            content.append("User: ").append(event.getUserId());
        }

        if (event.getSourceIp() != null) {
            if (!content.isEmpty()) content.append(", ");
            content.append("IP: ").append(event.getSourceIp());
        }

        String path = extractPath(event);
        if (path != null) {
            if (!content.isEmpty()) content.append(", ");
            content.append("Path: ").append(path);
        }

        String os = extractOSFromUserAgent(event.getUserAgent());
        if (os != null && !"Desktop".equals(os)) {
            if (!content.isEmpty()) content.append(", ");
            content.append("OS: ").append(os);
        }

        return content.toString();
    }

    private String extractHttpMethod(SecurityEvent event) {
        Map<String, Object> metadataObj = event.getMetadata();
        if (metadataObj instanceof Map) {
            Object method = metadataObj.get("httpMethod");
            if (method != null) {
                return method.toString();
            }
        }
        return null;
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

    private void storeThreatDocument(SecurityEvent event, SecurityDecision decision, String analysisContent) {
        try {
            Map<String, Object> threatMetadata = buildBaseMetadata(event, decision, VectorDocumentType.THREAT.getValue());

            if (decision.getBehaviorPatterns() != null && !decision.getBehaviorPatterns().isEmpty()) {
                threatMetadata.put("behaviorPatterns", String.join(", ", decision.getBehaviorPatterns()));
            }

            StringBuilder threatDesc = new StringBuilder("Contextual Threat:");

            if (event.getUserId() != null) {
                threatDesc.append(" User=").append(event.getUserId());
            }
            if (event.getSourceIp() != null) {
                threatDesc.append(", IP=").append(event.getSourceIp());
            }
            if (decision.getThreatCategory() != null) {
                threatDesc.append(", ThreatCategory=").append(decision.getThreatCategory());
            }
            if (decision.getBehaviorPatterns() != null && !decision.getBehaviorPatterns().isEmpty()) {
                threatDesc.append(", BehaviorPatterns=").append(decision.getBehaviorPatterns());
            }

            Document threatDoc = new Document(threatDesc.toString(), threatMetadata);
            unifiedVectorService.storeDocument(threatDoc);

        } catch (Exception e) {
            log.warn("[SecurityDecisionPostProcessor] 위협 패턴 저장 실패: eventId={}", event.getEventId(), e);
        }
    }

    private Map<String, Object> buildBaseMetadata(SecurityEvent event, SecurityDecision decision, String documentType) {
        Map<String, Object> metadata = new HashMap<>();

        metadata.put("documentType", documentType);

        String eventTimestamp = event.getTimestamp() != null
                ? event.getTimestamp().toString()
                : LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        metadata.put("timestamp", eventTimestamp);

        if (event.getTimestamp() != null) {
            metadata.put("hour", event.getTimestamp().getHour());
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

        if (decision.getThreatCategory() != null) {
            metadata.put("threatCategory", decision.getThreatCategory());
        }

        String requestPath = extractPath(event);
        if (requestPath != null) {
            metadata.put("requestPath", requestPath);
        }

        if (event.getUserAgent() != null && !event.getUserAgent().isEmpty()) {
            metadata.put("userAgent", event.getUserAgent());
            String userAgentOS = extractOSFromUserAgent(event.getUserAgent());
            if (userAgentOS != null) {
                metadata.put("userAgentOS", userAgentOS);
            }

            String browser = extractBrowserSignature(event.getUserAgent());
            if (browser != null) {
                metadata.put("userAgentBrowser", browser);
            }
        }

        return metadata;
    }

    private String extractOSFromUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return null;
        }

        if (userAgent.contains("Android")) {
            return "Android";
        }
        if (userAgent.contains("iPhone") || userAgent.contains("iPad") || userAgent.contains("iOS")) {
            return "iOS";
        }

        if (userAgent.contains("Windows NT") || userAgent.contains("Windows")) {
            return "Windows";
        }
        if (userAgent.contains("Mac OS X") || userAgent.contains("Macintosh")) {
            return "Mac";
        }
        if (userAgent.contains("CrOS")) {
            return "ChromeOS";
        }
        if (userAgent.contains("Linux")) {
            return "Linux";
        }

        if (userAgent.contains("Mobile") || userAgent.contains("Tablet")) {
            return "Mobile";
        }

        return "Desktop";
    }

    private String extractBrowserSignature(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return null;
        }

        if (userAgent.contains("Edg/") || userAgent.contains("Edge/")) {
            String version = extractBrowserVersion(userAgent, "Edg/");
            if (version == null) {
                version = extractBrowserVersion(userAgent, "Edge/");
            }
            return "Edge/" + (version != null ? version : "unknown");
        }

        if (userAgent.contains("Chrome/")) {
            String version = extractBrowserVersion(userAgent, "Chrome/");
            return "Chrome/" + (version != null ? version : "unknown");
        }

        if (userAgent.contains("Firefox/")) {
            String version = extractBrowserVersion(userAgent, "Firefox/");
            return "Firefox/" + (version != null ? version : "unknown");
        }

        if (userAgent.contains("Safari/") && !userAgent.contains("Chrome")) {

            String version = extractBrowserVersion(userAgent, "Version/");
            return "Safari/" + (version != null ? version : "unknown");
        }

        if (userAgent.contains("OPR/") || userAgent.contains("Opera/")) {
            String version = extractBrowserVersion(userAgent, "OPR/");
            if (version == null) {
                version = extractBrowserVersion(userAgent, "Opera/");
            }
            return "Opera/" + (version != null ? version : "unknown");
        }

        return null;
    }

    private String extractBrowserVersion(String userAgent, String prefix) {
        int startIndex = userAgent.indexOf(prefix);
        if (startIndex == -1) {
            return null;
        }

        startIndex += prefix.length();
        int endIndex = startIndex;

        while (endIndex < userAgent.length()) {
            char c = userAgent.charAt(endIndex);
            if (Character.isDigit(c) || c == '.') {
                endIndex++;
            } else {
                break;
            }
        }

        if (endIndex > startIndex) {
            String fullVersion = userAgent.substring(startIndex, endIndex);

            int dotIndex = fullVersion.indexOf('.');
            if (dotIndex > 0) {
                return fullVersion.substring(0, dotIndex);
            }
            return fullVersion;
        }

        return null;
    }
}
