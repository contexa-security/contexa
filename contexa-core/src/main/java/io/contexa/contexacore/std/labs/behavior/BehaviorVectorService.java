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

/**
 * 행동 분석 전용 벡터 저장소 서비스
 * 
 * BehavioralAnalysisLab을 위한 Spring AI 표준 준수 벡터 저장소 서비스입니다.
 * 행동 패턴 분석에 최적화된 메타데이터 강화 및 ETL 처리를 제공합니다.
 * 
 * @since 1.0.0
 */
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
    
    /**
     * AI Native v7.0: 메타데이터 강화 단순화
     * - 플랫폼 판단 필드 제거 (activityType, riskKeywords, behaviorSignature 등)
     * - 사실 데이터만 저장 (hour, dayOfWeek, isWeekend, networkSegment)
     * - 판단/분류는 LLM에 위임
     */
    @Override
    protected Document enrichLabSpecificMetadata(Document document) {
        Map<String, Object> metadata = new HashMap<>(document.getMetadata());

        try {
            // AI Native v7.0: 사실 데이터만 저장, 판단/분류는 LLM에 위임

            // 1. 시간 사실 데이터만 추가
            enrichTimeFactsOnly(metadata);

            // 2. 네트워크 사실 데이터만 추가
            enrichNetworkFactsOnly(metadata);

            // AI Native v7.0: 다음 필드들 제거 (플랫폼 판단 = 순환 로직 위험)
            // - activityType: 규칙 기반 분류 제거
            // - riskKeywords, hasRiskKeywords: 하드코딩 키워드 제거
            // - estimatedRoles, hasAdminRole: 플랫폼 추정 제거
            // - ipType, isInternalNetwork: 플랫폼 판단 제거
            // - isBusinessHours, isUnusualTime, timeSlot: 플랫폼 판단 제거
            // - behaviorSignature: 플랫폼 생성 제거
            // - enrichmentVersion, enrichedByService: 불필요 메타 제거

            return new Document(document.getText(), metadata);

        } catch (Exception e) {
            log.error("[BehaviorVectorService] 메타데이터 강화 실패", e);
            return new Document(document.getText(), metadata);
        }
    }

    /**
     * AI Native v7.0: 시간 사실 데이터만 추가
     * - 플랫폼 판단(isBusinessHours, isUnusualTime, timeSlot) 제거
     * - LLM이 hour, dayOfWeek, isWeekend를 보고 직접 판단
     */
    private void enrichTimeFactsOnly(Map<String, Object> metadata) {
        LocalDateTime now = LocalDateTime.now();

        metadata.put("hour", now.getHour());
        metadata.put("dayOfWeek", now.getDayOfWeek().toString());
        metadata.put("isWeekend", now.getDayOfWeek().getValue() >= 6);

        // AI Native v7.0: isBusinessHours, isUnusualTime, timeSlot 제거
        // LLM이 hour, dayOfWeek, isWeekend 사실 데이터를 보고 직접 판단
    }

    /**
     * AI Native v7.0: 네트워크 사실 데이터만 추가
     * - 플랫폼 판단(ipType, isInternalNetwork) 제거
     * - LLM이 networkSegment를 보고 직접 판단
     */
    private void enrichNetworkFactsOnly(Map<String, Object> metadata) {
        String ipAddress = (String) metadata.get("remoteIp");
        if (ipAddress != null && ipAddress.contains(".")) {
            int lastDot = ipAddress.lastIndexOf(".");
            if (lastDot > 0) {
                metadata.put("networkSegment", ipAddress.substring(0, lastDot));
            }
        }
        // AI Native v7.0: ipType, isInternalNetwork 제거
        // LLM이 networkSegment 사실 데이터를 보고 직접 판단
    }
    
    @Override
    protected void validateLabSpecificDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();
        
        // 필수 필드 검증
        if (!metadata.containsKey("userId") && 
            !metadata.containsKey("sessionId") && 
            !metadata.containsKey("ipAddress")) {
            throw new IllegalArgumentException(
                "행동 분석 문서는 userId, sessionId, ipAddress 중 최소 하나는 포함해야 합니다");
        }
        
        // 내용 검증
        String text = document.getText();
        if (text == null || text.trim().length() < 10) {
            throw new IllegalArgumentException("행동 분석 문서 내용이 너무 짧습니다 (최소 10자 필요)");
        }
        
        // 민감 정보 포함 여부 검증 (간단한 체크)
        if (containsSensitiveInfo(text)) {
            log.warn("[BehaviorVectorService] 문서에 민감 정보가 포함될 수 있습니다");
        }
    }
    
    /**
     * AI Native: riskThreshold 기반 판정 제거
     * - LLM이 riskScore를 직접 결정, 플랫폼은 저장/로깅만 수행
     * - requiresManualReview, alertTriggered 등은 LLM이 결정해야 함
     */
    @Override
    protected void postProcessDocument(Document document, OperationType operationType) {
        try {
            Map<String, Object> metadata = document.getMetadata();

            // AI Native: riskThreshold 기반 판정 제거 (LLM이 결정한 값 기록만)
            if (operationType == OperationType.STORE) {
                Double riskScore = (Double) metadata.get("riskScore");
                if (riskScore != null) {
                    log.info("[BehaviorVectorService][AI Native] 행동 저장: 사용자={}, riskScore={} (LLM 결정)",
                            metadata.get("userId"), riskScore);
                    // AI Native: alert/review 여부는 LLM이 결정해야 함, 규칙 기반 자동 설정 제거
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
    
    /**
     * 행동 패턴을 벡터 저장소에 저장 (확장된 시퀀스 및 컨텍스트 포함)
     *
     * @param context 행동 분석 컨텍스트
     */
    public void storeBehavior(BehavioralAnalysisContext context) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            // AI Native v7.0: "unknown" 폴백 제거 - null이면 필드 자체 생략
            if (context.getUserId() != null) {
                metadata.put("userId", context.getUserId());
            }
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));

            // 기본 활동 정보
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

            // 시퀀스 정보 추가
            if (context.getRecentActivitySequence() != null && !context.getRecentActivitySequence().isEmpty()) {
                metadata.put("activitySequence", context.getRecentActivitySequence());
                metadata.put("sequenceLength", context.getRecentActivitySequence().size());
                metadata.put("sequencePattern", context.getSequencePattern());
            }

            // 시간 간격 정보
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

            // 세션 및 디바이스 핑거프린트
            if (context.getSessionFingerprint() != null) {
                metadata.put("sessionFingerprint", context.getSessionFingerprint());
            } else {
                metadata.put("sessionId", UUID.randomUUID().toString());
            }
            if (context.getDeviceFingerprint() != null) {
                metadata.put("deviceFingerprint", context.getDeviceFingerprint());
            }

            // 디바이스 정보
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

            // 활동 빈도 및 속도
            metadata.put("dailyActivityCount", context.getDailyActivityCount());
            metadata.put("hourlyActivityCount", context.getHourlyActivityCount());
            metadata.put("activityVelocity", context.getActivityVelocity());

            // 활동 빈도 맵
            if (context.getActivityFrequency() != null && !context.getActivityFrequency().isEmpty()) {
                metadata.put("activityFrequency", context.getActivityFrequency());
                // 가장 빈번한 활동 찾기
                String mostFrequentActivity = context.getActivityFrequency().entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .map(Map.Entry::getKey)
                    .orElse(null);
                if (mostFrequentActivity != null) {
                    metadata.put("mostFrequentActivity", mostFrequentActivity);
                }
            }

            // AI Native v7.0: LLM 결과/플랫폼 판단 필드 제거
            // - behaviorAnomalyScore: LLM이 계산한 점수 (순환 로직 위험)
            // - anomalyIndicators: LLM이 생성한 이상 지표 (순환 로직 위험)
            // - hasRiskyPattern: 플랫폼 판단 (AI Native 위반)
            // - riskCategory: 플랫폼 판단 (AI Native 위반)

            // 컨텍스트 정보
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

            // 컨텍스트의 기존 메타데이터 병합
            if (context.getMetadata() != null && !context.getMetadata().isEmpty()) {
                for (Map.Entry<String, Object> entry : context.getMetadata().entrySet()) {
                    // 기존 키를 덮어쓰지 않도록 확인
                    if (!metadata.containsKey(entry.getKey())) {
                        metadata.put(entry.getKey(), entry.getValue());
                    }
                }
            }

            // AI Native v8.6: 행동 텍스트 생성 (Document-Query 형식 통일)
            // - "unknown" 폴백 제거: null이면 필드 자체 생략
            // - Path 추가: findSimilarBehaviors() 쿼리와 형식 일치
            // - 저장 형식: "User: admin, IP: x.x.x.x, Path: /api/xxx"
            StringBuilder behaviorText = new StringBuilder();

            if (context.getUserId() != null) {
                behaviorText.append("User: ").append(context.getUserId());
            }
            if (context.getRemoteIp() != null) {
                if (behaviorText.length() > 0) behaviorText.append(", ");
                behaviorText.append("IP: ").append(context.getRemoteIp());
            }
            // AI Native v8.6: Path 추가 (Document-Query 형식 통일)
            // metadata에서 requestUri를 가져옴 (Line 306-312에서 병합됨)
            String requestPath = null;
            if (context.getMetadata() != null) {
                Object pathObj = context.getMetadata().get("requestUri");
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

            log.debug("[BehaviorVectorService] 행동 패턴 저장 완료: 사용자={}, 시퀀스={}",
                context.getUserId(), context.getSequencePattern());

        } catch (Exception e) {
            log.error("[BehaviorVectorService] 행동 패턴 저장 실패", e);
            throw new VectorStoreException("행동 패턴 저장 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * 고위험 행동을 위협 패턴으로 저장 (미래 탐지용)
     *
     * 실제 운영 환경에서 발생한 고위험 행동(Risk >= 70.0)을
     * documentType="threat"로 저장하여 향후 유사한 공격 패턴 탐지에 활용
     *
     * @param context 행동 분석 컨텍스트
     * @param response 행동 분석 결과
     */
    public void storeThreatPattern(BehavioralAnalysisContext context, BehavioralAnalysisResponse response) {
        try {
            Map<String, Object> metadata = new HashMap<>();

            // AI Native v7.0: 위협 타입 메타데이터 (사실 데이터만)
            metadata.put("documentType", "threat");
            metadata.put("threatConfirmed", true);
            // AI Native v7.0: riskScore, behaviorAnomalyScore 제거 (LLM 결과 = 순환 로직)
            // AI Native v7.0: riskCategory 제거 (플랫폼 판단 = AI Native 위반)

            // AI Native v7.0: 위협 분류 - anomalyIndicators 원시 데이터만 저장
            // patternType, mitreTactic 제거 - 플랫폼이 판단하면 AI Native 위반
            // LLM이 anomalyIndicators를 참조하여 직접 판단
            List<String> indicators = context.getAnomalyIndicators();
            if (indicators != null && !indicators.isEmpty()) {
                metadata.put("threatIndicators", String.join(",", indicators));
            }
            // AI Native v7.0: patternType, mitreTactic 제거 (플랫폼 판단 = AI Native 위반)

            // IOC 지표 추출
            List<String> iocIndicators = extractIocIndicators(context);
            if (!iocIndicators.isEmpty()) {
                metadata.put("iocIndicators", String.join(",", iocIndicators));
            }

            // AI Native v7.0: 컨텍스트 정보 (사실 데이터만, "unknown" 폴백 제거)
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

            // 이상 지표
            if (context.getAnomalyIndicators() != null && !context.getAnomalyIndicators().isEmpty()) {
                metadata.put("anomalyIndicators", String.join(",", context.getAnomalyIndicators()));
            }

            // 위협 설명 생성
            String threatDescription = buildThreatDescription(context, response);
            Document threatDoc = new Document(threatDescription, metadata);

            storeDocument(threatDoc);

            // AI Native v7.0: 로그에서 riskScore 제거 (LLM 결과 = 순환 로직)
            log.info("[ThreatPattern] 위협 패턴 저장 완료: userId={}, indicators={}",
                context.getUserId(), metadata.get("threatIndicators"));

        } catch (Exception e) {
            log.error("[ThreatPattern] 위협 패턴 저장 실패: userId={}", context.getUserId(), e);
        }
    }

    // AI Native v7.0: determineThreatType() 삭제
    // 플랫폼이 위협 유형을 결정하면 AI Native 위반
    // LLM이 anomalyIndicators 원시 데이터를 보고 직접 판단

    // AI Native v7.0: mapToMitreTactic() 삭제
    // 플랫폼이 MITRE ATT&CK 전술을 매핑하면 AI Native 위반
    // LLM이 사실 데이터를 보고 MITRE 전술을 직접 판단

    /**
     * IOC 지표 추출
     *
     * AI Native v6.1: isSuspiciousUserAgent() 조건 제거
     * - 모든 User-Agent를 IOC에 포함 (LLM이 의심 여부 판단)
     * - 플랫폼이 "의심스러운 UA"를 판단하면 AI Native 위반
     */
    private List<String> extractIocIndicators(BehavioralAnalysisContext context) {
        List<String> indicators = new ArrayList<>();

        if (context.getRemoteIp() != null) {
            indicators.add("ip:" + context.getRemoteIp());
        }

        // AI Native v6.1: 모든 User-Agent를 IOC에 포함
        // isSuspiciousUserAgent() 조건 제거 - LLM이 판단하도록 위임
        if (context.getUserAgent() != null && !context.getUserAgent().isEmpty()) {
            indicators.add("ua:" + context.getUserAgent());
        }

        if (context.getSessionFingerprint() != null) {
            indicators.add("session:" + context.getSessionFingerprint());
        }

        return indicators;
    }

    // AI Native v7.0: isSuspiciousUserAgent() 삭제
    // 플랫폼이 User-Agent를 판단하면 AI Native 위반
    // LLM이 User-Agent 원시 데이터를 보고 직접 판단

    /**
     * 위협 설명 생성
     *
     * AI Native v7.0: LLM 결과(riskScore, summary) 제거
     * - 이전 LLM 분석 결과가 embedding에 포함되면 순환 로직 위험
     * - 사실 데이터만 포함 (userId, currentActivity, remoteIp, anomalyIndicators)
     * - "none" 기본값 제거 - null이면 필드 자체 생략
     */
    private String buildThreatDescription(BehavioralAnalysisContext context, BehavioralAnalysisResponse response) {
        // AI Native v7.0: 사실 데이터만 포함, LLM 결과 제거
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
        // AI Native v7.0: riskScore, summary 제거 (LLM 결과 = 순환 로직)
        return desc.toString();
    }

    // AI Native v7.0: determinePatternType() 삭제
    // 플랫폼이 패턴 유형(impossible_travel, bot_attack 등)을 결정하면 AI Native 위반
    // LLM이 사실 데이터(isNewDevice, isNewLocation, activityVelocity)를 보고 직접 판단

    /**
     * 분석 결과를 벡터 저장소에 저장
     *
     * AI Native v7.0: LLM 결과(riskScore, riskLevel, summary) 제거
     * - 이전 LLM 분석 결과가 다음 분석에 영향을 미치면 순환 로직 위험
     * - 사실 데이터만 저장 (userId, analysisId, timestamp, organizationId)
     * - "unknown" 폴백 제거 - null이면 필드 자체 생략
     *
     * @param context 행동 분석 컨텍스트
     * @param response 분석 결과
     */
    public void storeAnalysisResult(BehavioralAnalysisContext context, BehavioralAnalysisResponse response) {
        try {
            Map<String, Object> metadata = new HashMap<>();

            // AI Native v7.0: "unknown" 폴백 제거 - null이면 필드 자체 생략
            if (context.getUserId() != null) {
                metadata.put("userId", context.getUserId());
            }
            if (response.getAnalysisId() != null) {
                metadata.put("analysisId", response.getAnalysisId());
            } else {
                metadata.put("analysisId", UUID.randomUUID().toString());
            }
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));

            // AI Native v7.0: riskScore, riskLevel 제거 (LLM 결과 = 순환 로직)

            if (context.getOrganizationId() != null) {
                metadata.put("organizationId", context.getOrganizationId());
            }

            metadata.put("documentType", "behavior_analysis");

            // AI Native v7.0: embedding 텍스트에서 LLM 결과 제거 (사실 데이터만)
            StringBuilder analysisText = new StringBuilder("Analysis:");
            if (context.getUserId() != null) {
                analysisText.append(" User=").append(context.getUserId());
            }
            if (context.getOrganizationId() != null) {
                analysisText.append(", Org=").append(context.getOrganizationId());
            }
            // AI Native v7.0: riskScore, riskLevel, summary 제거 (LLM 결과 = 순환 로직)

            Document analysisDoc = new Document(analysisText.toString(), metadata);
            storeDocument(analysisDoc);

            log.debug("[BehaviorVectorService] 분석 결과 저장 완료: 분석ID={}", response.getAnalysisId());

        } catch (Exception e) {
            log.error("[BehaviorVectorService] 분석 결과 저장 실패", e);
            throw new VectorStoreException("분석 결과 저장 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * 피드백 정보를 벡터 저장소에 저장
     * 
     * @param analysisId 분석 ID
     * @param isCorrect 분석이 정확했는지 여부
     * @param feedback 피드백 내용
     */
    public void storeFeedback(String analysisId, boolean isCorrect, String feedback) {
        if (!feedbackLearningEnabled) {
            log.debug("📚 [BehaviorVectorService] 피드백 학습이 비활성화되어 있습니다");
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
            
            log.info("📚 [BehaviorVectorService] 피드백 저장 완료: 분석ID={}, 정확도={}", 
                    analysisId, isCorrect);
            
        } catch (Exception e) {
            log.error("[BehaviorVectorService] 피드백 저장 실패", e);
            throw new VectorStoreException("피드백 저장 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * 배치 학습 실행
     * 
     * @return 비동기 작업 결과
     */
    @Async
    public CompletableFuture<Void> runBatchLearning() {
        if (!batchLearningEnabled) {
            log.debug("📚 [BehaviorVectorService] 배치 학습이 비활성화되어 있습니다");
            return CompletableFuture.completedFuture(null);
        }
        
        return CompletableFuture.runAsync(() -> {
            try {
                log.info("📚 [BehaviorVectorService] 배치 학습 시작...");
                
                // 어제의 모든 감사 로그 조회
                LocalDateTime yesterday = LocalDateTime.now().minusDays(1);
                List<AuditLog> yesterdayLogs = auditLogRepository.findByTimestampBetween(
                    yesterday.withHour(0).withMinute(0),
                    yesterday.withHour(23).withMinute(59)
                );
                
                if (yesterdayLogs.isEmpty()) {
                    log.info("📚 [BehaviorVectorService] 배치 학습할 로그가 없습니다");
                    return;
                }
                
                // 배치 크기로 나누어 처리
                List<Document> batchDocuments = new ArrayList<>();
                
                for (AuditLog auditLog : yesterdayLogs) {
                    Document logDoc = convertAuditLogToDocument(auditLog);
                    batchDocuments.add(logDoc);
                    
                    // 배치 크기에 도달하면 저장
                    if (batchDocuments.size() >= labBatchSize) {
                        storeDocuments(new ArrayList<>(batchDocuments));
                        batchDocuments.clear();
                    }
                }
                
                // 남은 문서 저장
                if (!batchDocuments.isEmpty()) {
                    storeDocuments(batchDocuments);
                }
                
                log.info("[BehaviorVectorService] 배치 학습 완료: {}개 로그 처리", yesterdayLogs.size());
                
            } catch (Exception e) {
                log.error("[BehaviorVectorService] 배치 학습 실패", e);
                throw new VectorStoreException("배치 학습 실패: " + e.getMessage(), e);
            }
        });
    }
    
    /**
     * ETL 파이프라인을 통한 대량 데이터 처리
     * 
     * @param dataSource 데이터 소스
     * @param sourceType 소스 타입
     * @return ETL 작업 ID
     */
    public CompletableFuture<String> runETLPipeline(String dataSource, 
                                                  BehaviorETLPipeline.SourceType sourceType) {
        return behaviorETLPipeline.executePipeline(dataSource, sourceType);
    }
    
    
    
    
    
    
    
    /**
     * 감사 로그를 문서로 변환
     */
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
    
    /**
     * 민감 정보 포함 여부 검사
     */
    private boolean containsSensitiveInfo(String text) {
        String lowerText = text.toLowerCase();
        return lowerText.contains("password") || 
               lowerText.contains("ssn") || 
               lowerText.contains("credit") ||
               lowerText.contains("secret");
    }
    
    
    /**
     * 행동 컨텍스트를 벡터 저장소에 저장
     * BehavioralAnalysisContextRetriever와의 통합을 위한 메서드
     * 
     * @param context 행동 분석 컨텍스트
     */
    public void storeBehaviorContext(BehavioralAnalysisContext context) {
        storeBehavior(context); // 기존 storeBehavior 메서드 활용
    }
    
    /**
     * 유사한 행동 패턴 검색
     * BehavioralAnalysisContextRetriever와의 통합을 위한 메서드
     *
     * AI Native v8.6: Document-Query 형식 100% 통일
     * - 저장된 Document: "User: admin, IP: 0:0:0:0:0:0:0:1, Path: /api/xxx"
     * - 검색 Query: "User: admin, IP: 0:0:0:0:0:0:0:1, Path: /api/xxx"
     * - 형식 일치로 유사도 향상 (52% -> 90%+ 기대)
     *
     * @param userId 사용자 ID
     * @param ip 소스 IP 주소
     * @param path 요청 경로
     * @param topK 검색할 최대 문서 수
     * @return 유사한 행동 패턴 문서 목록
     */
    public List<Document> findSimilarBehaviors(String userId, String ip, String path, int topK) {
        try {
            Map<String, Object> filters = new HashMap<>();
            filters.put("documentType", "behavior");
            filters.put("userId", userId);
            filters.put("topK", topK);

            // AI Native v8.6: Document-Query 형식 통일
            // 저장된 문서와 동일한 형식으로 쿼리 생성
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