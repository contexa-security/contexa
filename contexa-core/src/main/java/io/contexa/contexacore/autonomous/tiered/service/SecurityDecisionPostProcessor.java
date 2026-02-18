package io.contexa.contexacore.autonomous.tiered.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
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
                    buildBehaviorSentence(event, decision)
            );

            redisTemplate.expire(sessionActionsKey, Duration.ofHours(24));

            Long size = redisTemplate.opsForList().size(sessionActionsKey);
            if (size != null && size > 100) {
                redisTemplate.opsForList().leftPop(sessionActionsKey);
            }

            ZeroTrustAction sessionAction = decision.getAction();
            if (sessionAction == ZeroTrustAction.BLOCK) {
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
            ZeroTrustAction action = decision.getAction();

            if (action == ZeroTrustAction.ALLOW) {
                storeBehaviorDocument(event, decision);
            }

            if (action == ZeroTrustAction.BLOCK) {
                String content = buildBehaviorContent(event, decision);
                storeThreatDocument(event, decision, content);
            }

        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    private void storeBehaviorDocument(SecurityEvent event, SecurityDecision decision) {
        try {
            String content = buildBehaviorSentence(event, decision);
            Map<String, Object> metadata = buildBaseMetadata(event, decision, VectorDocumentType.BEHAVIOR.getValue());

            Document document = new Document(content, metadata);
            unifiedVectorService.storeDocument(document);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    private String buildBehaviorSentence(SecurityEvent event, SecurityDecision decision) {
        StringBuilder sentence = new StringBuilder();

        if (event.getTimestamp() != null) {
            sentence.append(String.format("%02d:%02d",
                    event.getTimestamp().getHour(),
                    event.getTimestamp().getMinute()));
        }

        sentence.append(" | ");
        String method = null;
        String path = extractPath(event);
        if (event.getMetadata() != null) {
            Object m = event.getMetadata().get("httpMethod");
            if (m != null) method = m.toString();
        }
        if (method != null) sentence.append(method).append(" ");
        if (path != null) {
            sentence.append(path);
        } else if (event.getDescription() != null) {
            sentence.append(event.getDescription());
        }

        sentence.append(" | ");
        if (event.getSourceIp() != null) sentence.append(event.getSourceIp());

        sentence.append(" | ");
        String os = SecurityEventEnricher.extractOSFromUserAgent(event.getUserAgent());
        String browser = SecurityEventEnricher.extractBrowserSignature(event.getUserAgent());
        if (browser != null) sentence.append(browser);
        if (os != null) sentence.append("/").append(os);

        sentence.append(" | observed: ").append(decision.getAction().name().toLowerCase());

        return sentence.toString();
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

        String os = SecurityEventEnricher.extractOSFromUserAgent(event.getUserAgent());
        if (os != null && !"Desktop".equals(os)) {
            if (!content.isEmpty()) content.append(", ");
            content.append("OS: ").append(os);
        }

        return content.toString();
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
            log.error("[SecurityDecisionPostProcessor] Failed to store threat document: eventId={}", event.getEventId(), e);
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
            String userAgentOS = SecurityEventEnricher.extractOSFromUserAgent(event.getUserAgent());
            if (userAgentOS != null) {
                metadata.put("userAgentOS", userAgentOS);
            }

            String browser = SecurityEventEnricher.extractBrowserSignature(event.getUserAgent());
            if (browser != null) {
                metadata.put("userAgentBrowser", browser);
            }
        }

        return metadata;
    }

}
