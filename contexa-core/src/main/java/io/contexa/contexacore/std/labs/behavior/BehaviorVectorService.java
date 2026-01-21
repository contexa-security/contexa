package io.contexa.contexacore.std.labs.behavior;

import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.etl.BehaviorETLPipeline;
import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import io.contexa.contexacore.std.rag.service.StandardVectorStoreService;
import io.contexa.contexacommon.domain.context.BehavioralAnalysisContext;
import io.contexa.contexacommon.domain.response.BehavioralAnalysisResponse;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@Slf4j
public class BehaviorVectorService extends AbstractVectorLabService {
    
    private final BehaviorETLPipeline behaviorETLPipeline;
    private final AuditLogRepository auditLogRepository;
    
    @Value("${spring.ai.behavior.risk-threshold:60.0}")
    private double riskThreshold;
    
    @Value("${spring.ai.behavior.batch-learning-enabled:true}")
    private boolean batchLearningEnabled;
    
    @Value("${spring.ai.behavior.feedback-learning-enabled:true}")
    private boolean feedbackLearningEnabled;
    
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    @Autowired
    public BehaviorVectorService(StandardVectorStoreService standardVectorStoreService,
                                @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics,
                                BehaviorETLPipeline behaviorETLPipeline,
                                AuditLogRepository auditLogRepository) {
        super(standardVectorStoreService, vectorStoreMetrics);
        this.behaviorETLPipeline = behaviorETLPipeline;
        this.auditLogRepository = auditLogRepository;
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
            log.error("[BehaviorVectorService] 메타데이터 강화 실패", e);
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
                "행동 분석 문서는 userId, sessionId, ipAddress 중 최소 하나는 포함해야 합니다");
        }

        String text = document.getText();
        if (text == null || text.trim().length() < 10) {
            throw new IllegalArgumentException("행동 분석 문서 내용이 너무 짧습니다 (최소 10자 필요)");
        }

        if (containsSensitiveInfo(text)) {
            log.warn("[BehaviorVectorService] 문서에 민감 정보가 포함될 수 있습니다");
        }
    }

    @Override
    protected void postProcessDocument(Document document, OperationType operationType) {
        try {
            Map<String, Object> metadata = document.getMetadata();

            if (operationType == OperationType.STORE) {
                Double riskScore = (Double) metadata.get("riskScore");
                if (riskScore != null) {
                                        
                }
            }

        } catch (Exception e) {
            log.error("[BehaviorVectorService] 후처리 실패", e);
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

            if (context.getCurrentActivity() != null) {
                metadata.put("currentActivity", context.getCurrentActivity());
            }
            if (context.getPreviousActivity() != null) {
                metadata.put("previousActivity", context.getPreviousActivity());
            }
            if (context.getRemoteIp() != null) {
                metadata.put("remoteIp", context.getRemoteIp());
            }
            if (context.getOrganizationId() != null) {
                metadata.put("organizationId", context.getOrganizationId());
            }

            if (context.getRecentActivitySequence() != null && !context.getRecentActivitySequence().isEmpty()) {
                metadata.put("activitySequence", context.getRecentActivitySequence());
                metadata.put("sequenceLength", context.getRecentActivitySequence().size());
                metadata.put("sequencePattern", context.getSequencePattern());
            }

            if (context.getTimeSinceLastActivity() != null) {
                metadata.put("timeSinceLastActivity", context.getTimeSinceLastActivity().toSeconds());
            }
            if (context.getActivityIntervals() != null && !context.getActivityIntervals().isEmpty()) {
                List<Long> intervals = context.getActivityIntervals().stream()
                    .map(duration -> duration.toSeconds())
                    .toList();
                metadata.put("activityIntervals", intervals);
                if (!intervals.isEmpty()) {
                    double avgInterval = intervals.stream().mapToLong(Long::longValue).average().orElse(0);
                    metadata.put("avgActivityInterval", avgInterval);
                }
            }

            if (context.getSessionFingerprint() != null) {
                metadata.put("sessionFingerprint", context.getSessionFingerprint());
            } else {
                metadata.put("sessionId", UUID.randomUUID().toString());
            }
            if (context.getDeviceFingerprint() != null) {
                metadata.put("deviceFingerprint", context.getDeviceFingerprint());
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

            metadata.put("dailyActivityCount", context.getDailyActivityCount());
            metadata.put("hourlyActivityCount", context.getHourlyActivityCount());
            metadata.put("activityVelocity", context.getActivityVelocity());

            if (context.getActivityFrequency() != null && !context.getActivityFrequency().isEmpty()) {
                metadata.put("activityFrequency", context.getActivityFrequency());
                
                String mostFrequentActivity = context.getActivityFrequency().entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .map(Map.Entry::getKey)
                    .orElse(null);
                if (mostFrequentActivity != null) {
                    metadata.put("mostFrequentActivity", mostFrequentActivity);
                }
            }

            if (context.getAccessContext() != null) {
                metadata.put("accessContext", context.getAccessContext());
            }
            if (context.getGeoLocation() != null) {
                metadata.put("geoLocation", context.getGeoLocation());
            }
            if (context.getNetworkSegment() != null) {
                metadata.put("networkSegment", context.getNetworkSegment());
            }
            metadata.put("isVpnConnection", context.isVpnConnection());

            if (context.getMetadata() != null && !context.getMetadata().isEmpty()) {
                for (Map.Entry<String, Object> entry : context.getMetadata().entrySet()) {
                    
                    if (!metadata.containsKey(entry.getKey())) {
                        metadata.put(entry.getKey(), entry.getValue());
                    }
                }
            }

            StringBuilder behaviorText = new StringBuilder();

            if (context.getUserId() != null) {
                behaviorText.append("User: ").append(context.getUserId());
            }
            if (context.getRemoteIp() != null) {
                if (behaviorText.length() > 0) behaviorText.append(", ");
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
                if (behaviorText.length() > 0) behaviorText.append(", ");
                behaviorText.append("Path: ").append(requestPath);
            }
            if (context.getCurrentActivity() != null) {
                if (behaviorText.length() > 0) behaviorText.append(", ");
                behaviorText.append("Activity: ").append(context.getCurrentActivity());
            }
            if (context.getSequencePattern() != null && !"NO_SEQUENCE".equals(context.getSequencePattern())) {
                if (behaviorText.length() > 0) behaviorText.append(", ");
                behaviorText.append("Sequence: ").append(context.getSequencePattern());
            }

            Document behaviorDoc = new Document(behaviorText.toString(), metadata);
            storeDocument(behaviorDoc);

        } catch (Exception e) {
            log.error("[BehaviorVectorService] 행동 패턴 저장 실패", e);
            throw new VectorStoreException("행동 패턴 저장 실패: " + e.getMessage(), e);
        }
    }

    public void storeThreatPattern(BehavioralAnalysisContext context, BehavioralAnalysisResponse response) {
        try {
            Map<String, Object> metadata = new HashMap<>();

            metadata.put("documentType", "threat");
            metadata.put("threatConfirmed", true);

            List<String> indicators = context.getAnomalyIndicators();
            if (indicators != null && !indicators.isEmpty()) {
                metadata.put("threatIndicators", String.join(",", indicators));
            }

            List<String> iocIndicators = extractIocIndicators(context);
            if (!iocIndicators.isEmpty()) {
                metadata.put("iocIndicators", String.join(",", iocIndicators));
            }

            if (context.getUserId() != null) {
                metadata.put("userId", context.getUserId());
            }
            if (context.getCurrentActivity() != null) {
                metadata.put("currentActivity", context.getCurrentActivity());
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

            if (context.getAnomalyIndicators() != null && !context.getAnomalyIndicators().isEmpty()) {
                metadata.put("anomalyIndicators", String.join(",", context.getAnomalyIndicators()));
            }

            String threatDescription = buildThreatDescription(context, response);
            Document threatDoc = new Document(threatDescription, metadata);

            storeDocument(threatDoc);

        } catch (Exception e) {
            log.error("[ThreatPattern] 위협 패턴 저장 실패: userId={}", context.getUserId(), e);
        }
    }

    private List<String> extractIocIndicators(BehavioralAnalysisContext context) {
        List<String> indicators = new ArrayList<>();

        if (context.getRemoteIp() != null) {
            indicators.add("ip:" + context.getRemoteIp());
        }

        if (context.getUserAgent() != null && !context.getUserAgent().isEmpty()) {
            indicators.add("ua:" + context.getUserAgent());
        }

        if (context.getSessionFingerprint() != null) {
            indicators.add("session:" + context.getSessionFingerprint());
        }

        return indicators;
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

            if (context.getOrganizationId() != null) {
                metadata.put("organizationId", context.getOrganizationId());
            }

            metadata.put("documentType", "behavior_analysis");

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
            log.error("[BehaviorVectorService] 분석 결과 저장 실패", e);
            throw new VectorStoreException("분석 결과 저장 실패: " + e.getMessage(), e);
        }
    }

    public void storeFeedback(String analysisId, boolean isCorrect, String feedback) {
        if (!feedbackLearningEnabled) {
                        return;
        }
        
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("analysisId", analysisId);
            metadata.put("feedbackCorrect", isCorrect);
            metadata.put("feedbackText", feedback);
            metadata.put("feedbackTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "behavior_feedback");
            metadata.put("feedbackType", isCorrect ? "POSITIVE" : "NEGATIVE");
            
            String feedbackText = String.format(
                "분석 %s에 대한 피드백: %s - %s",
                analysisId,
                isCorrect ? "정확함" : "부정확함",
                feedback
            );
            
            Document feedbackDoc = new Document(feedbackText, metadata);
            storeDocument(feedbackDoc);

        } catch (Exception e) {
            log.error("[BehaviorVectorService] 피드백 저장 실패", e);
            throw new VectorStoreException("피드백 저장 실패: " + e.getMessage(), e);
        }
    }

    @Async
    public CompletableFuture<Void> runBatchLearning() {
        if (!batchLearningEnabled) {
                        return CompletableFuture.completedFuture(null);
        }
        
        return CompletableFuture.runAsync(() -> {
            try {

                LocalDateTime yesterday = LocalDateTime.now().minusDays(1);
                List<AuditLog> yesterdayLogs = auditLogRepository.findByTimestampBetween(
                    yesterday.withHour(0).withMinute(0),
                    yesterday.withHour(23).withMinute(59)
                );
                
                if (yesterdayLogs.isEmpty()) {
                                        return;
                }

                List<Document> batchDocuments = new ArrayList<>();
                
                for (AuditLog auditLog : yesterdayLogs) {
                    Document logDoc = convertAuditLogToDocument(auditLog);
                    batchDocuments.add(logDoc);

                    if (batchDocuments.size() >= labBatchSize) {
                        storeDocuments(new ArrayList<>(batchDocuments));
                        batchDocuments.clear();
                    }
                }

                if (!batchDocuments.isEmpty()) {
                    storeDocuments(batchDocuments);
                }

            } catch (Exception e) {
                log.error("[BehaviorVectorService] 배치 학습 실패", e);
                throw new VectorStoreException("배치 학습 실패: " + e.getMessage(), e);
            }
        });
    }

    public CompletableFuture<String> runETLPipeline(String dataSource, 
                                                  BehaviorETLPipeline.SourceType sourceType) {
        return behaviorETLPipeline.executePipeline(dataSource, sourceType);
    }

    private Document convertAuditLogToDocument(AuditLog auditLog) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", auditLog.getPrincipalName());
        metadata.put("timestamp", auditLog.getTimestamp().format(ISO_FORMATTER));
        metadata.put("action", auditLog.getAction());
        metadata.put("outcome", auditLog.getOutcome());
        metadata.put("clientIp", auditLog.getClientIp());
        metadata.put("documentType", "behavior_batch");
        metadata.put("isBatchLearning", true);
        
        String logText = String.format(
            "배치 학습: 사용자 %s가 %s에서 %s 작업을 수행했습니다. 결과: %s, 시간: %s",
            auditLog.getPrincipalName(),
            auditLog.getClientIp(),
            auditLog.getAction(),
            auditLog.getOutcome(),
            auditLog.getTimestamp()
        );
        
        return new Document(logText, metadata);
    }

    private boolean containsSensitiveInfo(String text) {
        String lowerText = text.toLowerCase();
        return lowerText.contains("password") || 
               lowerText.contains("ssn") || 
               lowerText.contains("credit") ||
               lowerText.contains("secret");
    }

    public void storeBehaviorContext(BehavioralAnalysisContext context) {
        storeBehavior(context); 
    }

    public List<Document> findSimilarBehaviors(String userId, String ip, String path, int topK) {
        try {
            Map<String, Object> filters = new HashMap<>();
            filters.put("documentType", "behavior");
            filters.put("userId", userId);
            filters.put("topK", topK);

            StringBuilder query = new StringBuilder();
            if (userId != null) {
                query.append("User: ").append(userId);
            }
            if (ip != null) {
                if (query.length() > 0) query.append(", ");
                query.append("IP: ").append(ip);
            }
            if (path != null) {
                if (query.length() > 0) query.append(", ");
                query.append("Path: ").append(path);
            }

            return searchSimilar(query.toString(), filters);
        } catch (Exception e) {
            log.error("[BehaviorVectorService] 유사 행동 패턴 검색 실패", e);
            return List.of();
        }
    }
}