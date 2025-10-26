package io.contexa.contexacore.std.labs.behavior;

import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.etl.BehaviorETLPipeline;
import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import io.contexa.contexacore.std.rag.service.StandardVectorStoreService;
import io.contexa.contexacore.dashboard.metrics.vectorstore.VectorStoreMetrics;
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
import java.util.regex.Pattern;

/**
 * 행동 분석 전용 벡터 저장소 서비스
 * 
 * BehavioralAnalysisLab을 위한 Spring AI 표준 준수 벡터 저장소 서비스입니다.
 * 행동 패턴 분석에 최적화된 메타데이터 강화 및 ETL 처리를 제공합니다.
 * 
 * @since 1.0.0
 */
@Slf4j
@Service
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
    
    // 활동 타입 분류를 위한 패턴
    private static final Map<String, Pattern> ACTIVITY_PATTERNS = Map.of(
        "LOGIN", Pattern.compile("login|authenticate|signin", Pattern.CASE_INSENSITIVE),
        "LOGOUT", Pattern.compile("logout|signout", Pattern.CASE_INSENSITIVE),
        "CREATE", Pattern.compile("create|insert|생성", Pattern.CASE_INSENSITIVE),
        "READ", Pattern.compile("read|select|view|조회", Pattern.CASE_INSENSITIVE),
        "UPDATE", Pattern.compile("update|modify|수정", Pattern.CASE_INSENSITIVE),
        "DELETE", Pattern.compile("delete|remove|삭제", Pattern.CASE_INSENSITIVE),
        "EXPORT", Pattern.compile("export|download", Pattern.CASE_INSENSITIVE),
        "ADMIN_ACTION", Pattern.compile("admin|configure|관리", Pattern.CASE_INSENSITIVE),
        "ACCESS_DENIED", Pattern.compile("denied|forbidden", Pattern.CASE_INSENSITIVE)
    );
    
    @Autowired
    public BehaviorVectorService(StandardVectorStoreService standardVectorStoreService,
                                VectorStoreMetrics vectorStoreMetrics,
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
            // 1. 활동 타입 분류
            String activityType = classifyActivityType(document.getText());
            metadata.put("activityType", activityType);
            
            // 2. 위험 키워드 분석
            Set<String> riskKeywords = analyzeRiskKeywords(document.getText());
            if (!riskKeywords.isEmpty()) {
                metadata.put("riskKeywords", new ArrayList<>(riskKeywords));
                metadata.put("hasRiskKeywords", true);
            } else {
                metadata.put("hasRiskKeywords", false);
            }
            
            // 3. 시간 기반 특성 분석
            enrichTimeBasedFeatures(metadata);
            
            // 4. 사용자 컨텍스트 강화
            enrichUserContext(metadata);
            
            // 5. 네트워크 컨텍스트 분석
            enrichNetworkContext(metadata);
            
            // 6. 행동 패턴 시그니처 생성
            String behaviorSignature = generateBehaviorSignature(metadata);
            metadata.put("behaviorSignature", behaviorSignature);
            
            // 7. 문서 버전 정보
            metadata.put("enrichmentVersion", "2.0");
            metadata.put("enrichedByService", "BehaviorVectorService");
            
            return new Document(document.getText(), metadata);
            
        } catch (Exception e) {
            log.error("[BehaviorVectorService] 메타데이터 강화 실패", e);
            // 오류 발생 시 기본 메타데이터라도 반환
            metadata.put("enrichmentError", e.getMessage());
            return new Document(document.getText(), metadata);
        }
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
    
    @Override
    protected void postProcessDocument(Document document, OperationType operationType) {
        try {
            Map<String, Object> metadata = document.getMetadata();
            
            // 고위험 행동 감지 시 알림
            if (operationType == OperationType.STORE) {
                Double riskScore = (Double) metadata.get("riskScore");
                if (riskScore != null && riskScore >= riskThreshold) {
                    log.warn("[BehaviorVectorService] 고위험 행동 감지: 사용자={}, 위험도={}, 활동={}", 
                            metadata.get("userId"), riskScore, metadata.get("activityType"));
                    
                    // 추가 모니터링 메타데이터 설정
                    metadata.put("requiresManualReview", true);
                    metadata.put("alertTriggered", true);
                    metadata.put("alertTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
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
            metadata.put("userId", context.getUserId() != null ? context.getUserId() : "unknown");
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

            // 위험 지표
            metadata.put("behaviorAnomalyScore", context.getBehaviorAnomalyScore());
            if (context.getAnomalyIndicators() != null && !context.getAnomalyIndicators().isEmpty()) {
                metadata.put("anomalyIndicators", context.getAnomalyIndicators());
            }
            metadata.put("hasRiskyPattern", context.isHasRiskyPattern());
            if (context.getRiskCategory() != null) {
                metadata.put("riskCategory", context.getRiskCategory());
            }

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

            // 행동 텍스트 생성 (시퀀스 패턴 포함)
            String behaviorText;
            if (context.getSequencePattern() != null && !"NO_SEQUENCE".equals(context.getSequencePattern())) {
                behaviorText = String.format(
                    "사용자 %s가 %s에서 행동 시퀀스 [%s]를 수행. 현재 활동: %s, 이상 점수: %.2f, 시간: %s",
                    context.getUserId() != null ? context.getUserId() : "unknown",
                    context.getRemoteIp() != null ? context.getRemoteIp() : "unknown",
                    context.getSequencePattern(),
                    context.getCurrentActivity() != null ? context.getCurrentActivity() : "unknown",
                    context.getBehaviorAnomalyScore(),
                    LocalDateTime.now()
                );
            } else {
                behaviorText = String.format(
                    "사용자 %s가 %s에서 %s 활동을 수행했습니다. 이상 점수: %.2f, 시간: %s",
                    context.getUserId() != null ? context.getUserId() : "unknown",
                    context.getRemoteIp() != null ? context.getRemoteIp() : "unknown",
                    context.getCurrentActivity() != null ? context.getCurrentActivity() : "unknown",
                    context.getBehaviorAnomalyScore(),
                    LocalDateTime.now()
                );
            }

            Document behaviorDoc = new Document(behaviorText, metadata);
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

            // 위협 타입 메타데이터
            metadata.put("documentType", "threat");  // ✅ 위협 패턴으로 분류
            metadata.put("threatConfirmed", true);
            metadata.put("riskScore", response.getBehavioralRiskScore());
            metadata.put("behaviorAnomalyScore", context.getBehaviorAnomalyScore());

            // 위협 분류
            metadata.put("threatType", determineThreatType(context));
            metadata.put("riskCategory", context.getRiskCategory() != null ? context.getRiskCategory() : "UNKNOWN");
            metadata.put("patternType", determinePatternType(context));

            // MITRE ATT&CK 매핑
            metadata.put("mitreTactic", mapToMitreTactic(context));

            // IOC 지표 추출
            List<String> iocIndicators = extractIocIndicators(context);
            if (!iocIndicators.isEmpty()) {
                metadata.put("iocIndicators", String.join(",", iocIndicators));
            }

            // 컨텍스트 정보
            metadata.put("userId", context.getUserId());
            metadata.put("currentActivity", context.getCurrentActivity());
            metadata.put("remoteIp", context.getRemoteIp() != null ? context.getRemoteIp() : "unknown");
            metadata.put("userAgent", context.getUserAgent() != null ? context.getUserAgent() : "unknown");
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

            log.info("[ThreatPattern] 위협 패턴 저장 완료: userId={}, riskScore={}, threatType={}",
                context.getUserId(), response.getBehavioralRiskScore(), metadata.get("threatType"));

        } catch (Exception e) {
            log.error("[ThreatPattern] 위협 패턴 저장 실패: userId={}", context.getUserId(), e);
        }
    }

    /**
     * 위협 유형 결정
     */
    private String determineThreatType(BehavioralAnalysisContext context) {
        if (context.getAnomalyIndicators() != null) {
            Set<String> indicators = new HashSet<>(context.getAnomalyIndicators());

            if (indicators.contains("brute_force") || indicators.contains("repeated_failed_login")) {
                return "BRUTE_FORCE";
            }
            if (indicators.contains("session_hijacking") || indicators.contains("token_reuse")) {
                return "SESSION_HIJACKING";
            }
            if (indicators.contains("data_exfiltration") || indicators.contains("bulk_access")) {
                return "DATA_EXFILTRATION";
            }
            if (indicators.contains("privilege_escalation")) {
                return "PRIVILEGE_ESCALATION";
            }
            if (indicators.contains("sql_injection") || indicators.contains("xss")) {
                return "INJECTION_ATTACK";
            }
        }

        // 활동 기반 분류
        String activity = context.getCurrentActivity();
        if (activity != null) {
            if (activity.contains("admin") || activity.contains("config")) {
                return "UNAUTHORIZED_ACCESS";
            }
            if (activity.contains("download") || activity.contains("export")) {
                return "DATA_EXFILTRATION";
            }
        }

        return "UNKNOWN_THREAT";
    }

    /**
     * MITRE ATT&CK 전술 매핑
     */
    private String mapToMitreTactic(BehavioralAnalysisContext context) {
        String threatType = determineThreatType(context);
        return switch (threatType) {
            case "BRUTE_FORCE" -> "TA0006:CredentialAccess";
            case "SESSION_HIJACKING" -> "TA0006:CredentialAccess";
            case "DATA_EXFILTRATION" -> "TA0010:Exfiltration";
            case "PRIVILEGE_ESCALATION" -> "TA0004:PrivilegeEscalation";
            case "INJECTION_ATTACK" -> "TA0001:InitialAccess";
            case "UNAUTHORIZED_ACCESS" -> "TA0005:DefenseEvasion";
            default -> "TA0043:Reconnaissance";
        };
    }

    /**
     * IOC 지표 추출
     */
    private List<String> extractIocIndicators(BehavioralAnalysisContext context) {
        List<String> indicators = new ArrayList<>();

        if (context.getRemoteIp() != null) {
            indicators.add("ip:" + context.getRemoteIp());
        }

        if (context.getUserAgent() != null && isSuspiciousUserAgent(context.getUserAgent())) {
            indicators.add("ua:" + context.getUserAgent());
        }

        if (context.getSessionFingerprint() != null) {
            indicators.add("session:" + context.getSessionFingerprint());
        }

        return indicators;
    }

    /**
     * 의심스러운 User-Agent 판별
     */
    private boolean isSuspiciousUserAgent(String userAgent) {
        String ua = userAgent.toLowerCase();
        return ua.contains("curl") || ua.contains("wget") || ua.contains("python") ||
               ua.contains("bot") || ua.contains("scanner") || ua.contains("sqlmap") ||
               ua.contains("nikto") || ua.contains("nmap");
    }

    /**
     * 위협 설명 생성
     */
    private String buildThreatDescription(BehavioralAnalysisContext context, BehavioralAnalysisResponse response) {
        // 이상 지표 문자열 생성
        String anomalyStr = context.getAnomalyIndicators() != null && !context.getAnomalyIndicators().isEmpty()
            ? String.join(", ", context.getAnomalyIndicators())
            : "none";

        return String.format(
            "고위험 행동 탐지: 사용자=%s, 활동=%s, IP=%s, 위험도=%.2f, " +
            "위협유형=%s, 지표=%s, 분석요약=%s",
            context.getUserId(),
            context.getCurrentActivity(),
            context.getRemoteIp(),
            response.getBehavioralRiskScore(),
            determineThreatType(context),
            anomalyStr,
            response.getSummary() != null ? response.getSummary() : "none"
        );
    }

    /**
     * 패턴 유형 결정
     */
    private String determinePatternType(BehavioralAnalysisContext context) {
        if (context.isNewDevice() && context.isNewLocation()) {
            return "impossible_travel";
        }
        if (context.getActivityVelocity() > 100.0) {
            return "bot_attack";
        }
        if (context.getAnomalyIndicators() != null &&
            (context.getAnomalyIndicators().contains("brute_force") ||
             context.getAnomalyIndicators().contains("repeated_failed_login"))) {
            return "brute_force";
        }
        return "suspicious_behavior";
    }

    /**
     * 분석 결과를 벡터 저장소에 저장
     *
     * @param context 행동 분석 컨텍스트
     * @param response 분석 결과
     */
    public void storeAnalysisResult(BehavioralAnalysisContext context, BehavioralAnalysisResponse response) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("userId", context.getUserId() != null ? context.getUserId() : "unknown");
            metadata.put("analysisId", response.getAnalysisId() != null ? response.getAnalysisId() : UUID.randomUUID().toString());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("riskScore", response.getBehavioralRiskScore());

            if (response.getRiskLevel() != null) {
                metadata.put("riskLevel", response.getRiskLevel().toString());
            }
            if (context.getOrganizationId() != null) {
                metadata.put("organizationId", context.getOrganizationId());
            }

            metadata.put("documentType", "behavior_analysis");
            metadata.put("isAnomaly", response.getBehavioralRiskScore() > riskThreshold);

            // 이상 징후 정보 추가
            if (response.getAnomalies() != null && !response.getAnomalies().isEmpty()) {
                List<String> anomalyTypes = response.getAnomalies().stream()
                    .map(anomaly -> anomaly.getType())
                    .filter(type -> type != null)
                    .toList();
                if (!anomalyTypes.isEmpty()) {
                    metadata.put("anomalyTypes", anomalyTypes);
                }
            }

            String analysisText = String.format(
                "사용자 %s의 행동 분석 결과: 위험도 %.1f (%s) - %s",
                context.getUserId() != null ? context.getUserId() : "unknown",
                response.getBehavioralRiskScore(),
                response.getRiskLevel() != null ? response.getRiskLevel() : "UNKNOWN",
                response.getSummary() != null ? response.getSummary() : ""
            );
            
            Document analysisDoc = new Document(analysisText, metadata);
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
     * 활동 타입 분류
     */
    private String classifyActivityType(String content) {
        if (content == null) return "UNKNOWN";
        
        for (Map.Entry<String, Pattern> entry : ACTIVITY_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(content).find()) {
                return entry.getKey();
            }
        }
        
        return "OTHER";
    }
    
    /**
     * 위험 키워드 분석
     */
    private Set<String> analyzeRiskKeywords(String content) {
        Set<String> riskKeywords = new HashSet<>();
        
        if (content == null) return riskKeywords;
        
        String lowerContent = content.toLowerCase();
        
        // 위험 키워드 목록
        Set<String> keywords = Set.of(
            "delete", "remove", "drop", "truncate", "admin", "root", "sudo",
            "password", "credential", "secret", "token", "key", "certificate",
            "export", "download", "transfer", "copy", "backup", "restore"
        );
        
        for (String keyword : keywords) {
            if (lowerContent.contains(keyword)) {
                riskKeywords.add(keyword);
            }
        }
        
        return riskKeywords;
    }
    
    /**
     * 시간 기반 특성 강화
     */
    private void enrichTimeBasedFeatures(Map<String, Object> metadata) {
        LocalDateTime now = LocalDateTime.now();
        
        // 시간대 정보
        int hour = now.getHour();
        metadata.put("hour", hour);
        metadata.put("dayOfWeek", now.getDayOfWeek().toString());
        metadata.put("isWeekend", now.getDayOfWeek().getValue() >= 6);
        
        // 업무 시간 여부
        boolean isBusinessHours = hour >= 9 && hour < 18 && now.getDayOfWeek().getValue() <= 5;
        metadata.put("isBusinessHours", isBusinessHours);
        
        // 비정상 시간대 여부
        boolean isUnusualTime = hour >= 22 || hour < 6 || now.getDayOfWeek().getValue() >= 6;
        metadata.put("isUnusualTime", isUnusualTime);
        
        // 시간 구간 분류
        String timeSlot;
        if (hour >= 6 && hour < 9) timeSlot = "EARLY_MORNING";
        else if (hour >= 9 && hour < 12) timeSlot = "MORNING";
        else if (hour >= 12 && hour < 14) timeSlot = "LUNCH";
        else if (hour >= 14 && hour < 18) timeSlot = "AFTERNOON";
        else if (hour >= 18 && hour < 22) timeSlot = "EVENING";
        else timeSlot = "NIGHT";
        
        metadata.put("timeSlot", timeSlot);
    }
    
    /**
     * 사용자 컨텍스트 강화
     */
    private void enrichUserContext(Map<String, Object> metadata) {
        String userId = (String) metadata.get("userId");
        if (userId != null) {
            // 간단한 사용자 역할 추정 (실제로는 DB에서 조회)
            List<String> estimatedRoles = estimateUserRoles(userId);
            if (!estimatedRoles.isEmpty()) {
                metadata.put("estimatedRoles", estimatedRoles);
                metadata.put("hasAdminRole", estimatedRoles.stream()
                    .anyMatch(role -> role.contains("ADMIN") || role.contains("ROOT")));
            }
        }
    }
    
    /**
     * 네트워크 컨텍스트 강화
     */
    private void enrichNetworkContext(Map<String, Object> metadata) {
        String ipAddress = (String) metadata.get("remoteIp");
        if (ipAddress != null) {
            // IP 주소 타입 분류
            if (isInternalNetwork(ipAddress)) {
                metadata.put("ipType", "INTERNAL");
                metadata.put("isInternalNetwork", true);
            } else {
                metadata.put("ipType", "EXTERNAL");
                metadata.put("isInternalNetwork", false);
            }
            
            // 네트워크 세그먼트
            metadata.put("networkSegment", ipAddress.substring(0, ipAddress.lastIndexOf(".")));
        }
    }
    
    /**
     * 행동 패턴 시그니처 생성
     */
    private String generateBehaviorSignature(Map<String, Object> metadata) {
        StringBuilder signature = new StringBuilder();
        
        signature.append(metadata.getOrDefault("activityType", "UNKNOWN"));
        signature.append("-");
        signature.append(metadata.getOrDefault("timeSlot", "UNKNOWN"));
        signature.append("-");
        signature.append(metadata.getOrDefault("ipType", "UNKNOWN"));
        
        if (Boolean.TRUE.equals(metadata.get("hasRiskKeywords"))) {
            signature.append("-RISK");
        }
        
        if (Boolean.TRUE.equals(metadata.get("isUnusualTime"))) {
            signature.append("-UNUSUAL");
        }
        
        return signature.toString();
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
     * 사용자 역할 추정
     */
    private List<String> estimateUserRoles(String userId) {
        // 실제로는 IAM 시스템에서 조회해야 함
        if (userId.contains("admin")) {
            return List.of("ADMIN", "USER");
        }
        return List.of("USER");
    }
    
    /**
     * 내부 네트워크 여부 확인
     */
    private boolean isInternalNetwork(String ipAddress) {
        return ipAddress.startsWith("10.") || 
               ipAddress.startsWith("192.168.") ||
               ipAddress.startsWith("172.16.") || 
               ipAddress.startsWith("127.");
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
     * @param userId 사용자 ID
     * @param activity 현재 활동
     * @param topK 검색할 최대 문서 수
     * @return 유사한 행동 패턴 문서 목록
     */
    public List<Document> findSimilarBehaviors(String userId, String activity, int topK) {
        try {
            Map<String, Object> filters = new HashMap<>();
            filters.put("documentType", "behavior");
            filters.put("userId", userId);
            filters.put("topK", topK);
            
            String query = String.format("사용자 %s의 %s 활동 패턴", userId, activity);
            return searchSimilar(query, filters);
        } catch (Exception e) {
            log.error("[BehaviorVectorService] 유사 행동 패턴 검색 실패", e);
            return List.of();
        }
    }
}