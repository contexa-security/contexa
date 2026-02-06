package io.contexa.contexacore.std.labs.behavior;

import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.etl.BehaviorETLPipeline;
import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import org.springframework.ai.vectorstore.VectorStore;
import io.contexa.contexacommon.domain.context.BehavioralAnalysisContext;
import io.contexa.contexacommon.domain.response.BehavioralAnalysisResponse;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@Slf4j
public class BehaviorVectorService extends AbstractVectorLabService {

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    @Autowired
    public BehaviorVectorService(VectorStore vectorStore,
                                @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        super(vectorStore, vectorStoreMetrics);
    }

    @Override
    protected String getLabName() {
        return "BehavioralAnalysis";
    }

    @Override
    protected String getDocumentType() {
        return VectorDocumentType.BEHAVIOR.getValue();
    }

    @Override
    protected Document enrichLabSpecificMetadata(Document document) {
        Map<String, Object> metadata = new HashMap<>(document.getMetadata());

        try {

            enrichTimeFactsOnly(metadata);
            enrichNetworkFactsOnly(metadata);

            return new Document(document.getText(), metadata);

        } catch (Exception e) {
            log.error("[BehaviorVectorService] Metadata enrichment failed", e);
            return new Document(document.getText(), metadata);
        }
    }

    private void enrichTimeFactsOnly(Map<String, Object> metadata) {
        LocalDateTime now = LocalDateTime.now();

        metadata.put("hour", now.getHour());
        metadata.put("dayOfWeek", now.getDayOfWeek().toString());
        metadata.put("isWeekend", now.getDayOfWeek().getValue() >= 6);

    }

    private void enrichNetworkFactsOnly(Map<String, Object> metadata) {
        String ipAddress = (String) metadata.get("remoteIp");
        if (ipAddress != null && ipAddress.contains(".")) {
            int lastDot = ipAddress.lastIndexOf(".");
            if (lastDot > 0) {
                metadata.put("networkSegment", ipAddress.substring(0, lastDot));
            }
        }

    }

    @Override
    protected void validateLabSpecificDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();

        if (!metadata.containsKey("userId") &&
            !metadata.containsKey("sessionId") &&
            !metadata.containsKey("ipAddress")) {
            throw new IllegalArgumentException(
                "Behavior analysis document must contain at least one of userId, sessionId, or ipAddress");
        }

        String text = document.getText();
        if (text == null || text.trim().length() < 10) {
            throw new IllegalArgumentException("Behavior analysis document content too short (minimum 10 characters required)");
        }
    }

    @Override
    protected Map<String, Object> getLabSpecificFilters() {
        Map<String, Object> filters = new HashMap<>();
        filters.put("labName", getLabName());
        return filters;
    }

    public void storeBehavior(BehavioralAnalysisContext context) {
        try {
            Map<String, Object> metadata = new HashMap<>();

            if (context.getUserId() != null) {
                metadata.put("userId", context.getUserId());
            }
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));

            if (context.getRemoteIp() != null) {
                metadata.put("remoteIp", context.getRemoteIp());
            }

            if (context.getSessionFingerprint() != null) {
                metadata.put("sessionId", context.getSessionFingerprint());
            } else {
                metadata.put("sessionId", UUID.randomUUID().toString());
            }

            if (context.getUserAgent() != null) {
                metadata.put("userAgent", context.getUserAgent());
            }
            if (context.getBrowserInfo() != null) {
                metadata.put("browserInfo", context.getBrowserInfo());
            }
            if (context.getOsInfo() != null) {
                metadata.put("osInfo", context.getOsInfo());
            }
            metadata.put("isNewDevice", context.isNewDevice());
            metadata.put("isNewLocation", context.isNewLocation());

            StringBuilder behaviorText = new StringBuilder();

            if (context.getUserId() != null) {
                behaviorText.append("User: ").append(context.getUserId());
            }
            if (context.getRemoteIp() != null) {
                if (!behaviorText.isEmpty()) behaviorText.append(", ");
                behaviorText.append("IP: ").append(context.getRemoteIp());
            }

            String requestPath = null;
            if (context.getMetadata() != null) {
                Object pathObj = context.getMetadata().get("requestPath");
                if (pathObj != null) {
                    requestPath = pathObj.toString();
                }
            }
            if (requestPath != null) {
                if (!behaviorText.isEmpty()) behaviorText.append(", ");
                behaviorText.append("Path: ").append(requestPath);
            }
            if (context.getCurrentActivity() != null) {
                if (!behaviorText.isEmpty()) behaviorText.append(", ");
                behaviorText.append("Activity: ").append(context.getCurrentActivity());
            }
            if (context.getSequencePattern() != null && !"NO_SEQUENCE".equals(context.getSequencePattern())) {
                if (!behaviorText.isEmpty()) behaviorText.append(", ");
                behaviorText.append("Sequence: ").append(context.getSequencePattern());
            }

            Document behaviorDoc = new Document(behaviorText.toString(), metadata);
            storeDocument(behaviorDoc);

        } catch (Exception e) {
            log.error("[BehaviorVectorService] Behavior pattern storage failed", e);
            throw new VectorStoreException("Behavior pattern storage failed: " + e.getMessage(), e);
        }
    }

    public void storeThreatPattern(BehavioralAnalysisContext context, BehavioralAnalysisResponse response) {
        try {
            Map<String, Object> metadata = new HashMap<>();

            metadata.put("documentType", VectorDocumentType.THREAT.getValue());

            if (context.getUserId() != null) {
                metadata.put("userId", context.getUserId());
            }
            if (context.getRemoteIp() != null) {
                metadata.put("remoteIp", context.getRemoteIp());
            }
            if (context.getUserAgent() != null) {
                metadata.put("userAgent", context.getUserAgent());
            }
            metadata.put("isNewDevice", context.isNewDevice());
            metadata.put("isNewLocation", context.isNewLocation());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));

            String threatDescription = buildThreatDescription(context, response);
            Document threatDoc = new Document(threatDescription, metadata);

            storeDocument(threatDoc);

        } catch (Exception e) {
            log.error("[ThreatPattern] Threat pattern storage failed: userId={}", context.getUserId(), e);
        }
    }

    private String buildThreatDescription(BehavioralAnalysisContext context, BehavioralAnalysisResponse response) {

        StringBuilder desc = new StringBuilder("Threat:");
        if (context.getUserId() != null) {
            desc.append(" User=").append(context.getUserId());
        }
        if (context.getCurrentActivity() != null) {
            desc.append(", Activity=").append(context.getCurrentActivity());
        }
        if (context.getRemoteIp() != null) {
            desc.append(", IP=").append(context.getRemoteIp());
        }
        if (context.getAnomalyIndicators() != null && !context.getAnomalyIndicators().isEmpty()) {
            desc.append(", Indicators=").append(String.join(",", context.getAnomalyIndicators()));
        }

        return desc.toString();
    }

    public void storeAnalysisResult(BehavioralAnalysisContext context, BehavioralAnalysisResponse response) {
        try {
            Map<String, Object> metadata = new HashMap<>();

            if (context.getUserId() != null) {
                metadata.put("userId", context.getUserId());
            }
            if (response.getAnalysisId() != null) {
                metadata.put("analysisId", response.getAnalysisId());
            } else {
                metadata.put("analysisId", UUID.randomUUID().toString());
            }
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));

            metadata.put("documentType", VectorDocumentType.BEHAVIOR_ANALYSIS.getValue());

            StringBuilder analysisText = new StringBuilder("Analysis:");
            if (context.getUserId() != null) {
                analysisText.append(" User=").append(context.getUserId());
            }
            if (context.getOrganizationId() != null) {
                analysisText.append(", Org=").append(context.getOrganizationId());
            }

            Document analysisDoc = new Document(analysisText.toString(), metadata);
            storeDocument(analysisDoc);

        } catch (Exception e) {
            log.error("[BehaviorVectorService] Analysis result storage failed", e);
            throw new VectorStoreException("Analysis result storage failed: " + e.getMessage(), e);
        }
    }

    public List<Document> findSimilarBehaviors(String userId, String ip, String path, int topK) {
        try {
            Map<String, Object> filters = new HashMap<>();
            filters.put("userId", userId);
            filters.put("topK", topK);

            StringBuilder query = new StringBuilder();
            if (userId != null) {
                query.append("User: ").append(userId);
            }
            if (ip != null) {
                if (!query.isEmpty()) query.append(", ");
                query.append("IP: ").append(ip);
            }
            if (path != null) {
                if (!query.isEmpty()) query.append(", ");
                query.append("Path: ").append(path);
            }

            return searchSimilar(query.toString(), filters);
        } catch (Exception e) {
            log.error("[BehaviorVectorService] Similar behavior pattern search failed", e);
            return List.of();
        }
    }
}
