package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexacore.std.operations.AICoreOperations;
// AI Native: MitreAttackEvaluationStrategy, NistCsfEvaluationStrategy, CisControlsEvaluationStrategy 제거
// LLM과 연동되지 않는 규칙 기반 Strategy는 AI Native 아키텍처에서 사용하지 않음
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.AbstractAISecurityExpressionRoot;
import io.contexa.contexaiam.security.xacml.pip.attribute.AttributeInformationPoint;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.RiskAssessmentRequest;
import io.contexa.contexacommon.domain.response.RiskAssessmentResponse;
import io.contexa.contexacommon.dto.UserDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.List;
import java.util.ArrayList;
import jakarta.servlet.http.HttpServletRequest;

/**
 * 실시간 AI 보안 표현식 루트 (극히 예외적인 고위험 작업용)
 * 
 * 실제로 AI를 호출하여 실시간 분석을 수행합니다.
 * 매우 느릴 수 있으므로 고위험 금융 거래, 특권 작업 등에만 사용됩니다.
 * 
 * 외부기관 설계에 따른 계층 구조:
 * AbstractAISecurityExpressionRoot (공통 기반)
 *   └── RealtimeAISecurityExpressionRoot (이 클래스)
 * 
 * 사용 예시:
 * - @PreAuthorize("#ai.analyzeFraud(#transaction)")
 * - @PreAuthorize("#ai.detectAnomaly(#operation)")
 * - @PreAuthorize("#ai.evaluateCriticalOperation(#context)")
 */
@Slf4j
public class RealtimeAISecurityExpressionRoot extends AbstractAISecurityExpressionRoot {

    // AI Native: MitreAttackEvaluationStrategy, NistCsfEvaluationStrategy, CisControlsEvaluationStrategy 제거
    // LLM과 연동되지 않는 규칙 기반 Strategy는 AI Native 아키텍처에서 사용하지 않음
    // 이상 탐지, 권한 상승 평가 등은 AICoreOperations를 통한 LLM 호출로 처리

    // AI 호출 타임아웃 설정
    private static final Duration AI_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration CRITICAL_AI_TIMEOUT = Duration.ofSeconds(60);
    
    // 위험 임계값
    private static final double FRAUD_THRESHOLD = 0.7;
    private static final double ANOMALY_THRESHOLD = 0.6;
    private static final double CRITICAL_THRESHOLD = 0.8;
    
    public RealtimeAISecurityExpressionRoot(Authentication authentication,
                                            AttributeInformationPoint attributePIP,
                                            AICoreOperations aINativeProcessor,
                                            AuthorizationContext authorizationContext,
                                            AuditLogRepository auditLogRepository) {
        super(authentication, attributePIP, aINativeProcessor, authorizationContext, auditLogRepository);
        log.info("RealtimeAISecurityExpressionRoot 초기화 - 실시간 AI 분석 모드");
    }
    
    /**
     * 사기 거래 분석 (금융 거래용)
     * 
     * @param transaction 거래 정보 맵
     * @return 사기가 아닌 정상 거래면 true
     */
    public boolean analyzeFraud(Map<String, Object> transaction) {
        if (transaction == null || transaction.isEmpty()) {
            log.warn("analyzeFraud: 거래 정보가 없음");
            return false; // 안전을 위해 거부
        }
        
        String userId = extractUserId();
        if (userId == null) {
            log.warn("analyzeFraud: 사용자 ID를 추출할 수 없음");
            return false;
        }
        
        try {
            log.info("사기 거래 분석 시작 - userId: {}, amount: {}", 
                    userId, transaction.get("amount"));
            
            // FraudAnalysisContext 생성
            FraudAnalysisContext context = new FraudAnalysisContext();
            context.setUserId(userId);
            context.setTransactionId(String.valueOf(transaction.get("id")));
            context.setAmount(Double.valueOf(String.valueOf(transaction.get("amount"))));
            context.setCurrency(String.valueOf(transaction.get("currency")));
            context.setMerchant(String.valueOf(transaction.get("merchant")));
            context.setTimestamp(LocalDateTime.now());
            context.setSourceIp(getRemoteIp());
            context.setDeviceId(String.valueOf(transaction.get("deviceId")));
            
            // 추가 메타데이터
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("transactionType", transaction.get("type"));
            metadata.put("paymentMethod", transaction.get("paymentMethod"));
            metadata.put("location", transaction.get("location"));
            // metadata를 DomainContext의 addMetadata 메서드로 추가
            if (metadata != null) {
                for (Map.Entry<String, Object> entry : metadata.entrySet()) {
                    context.addMetadata(entry.getKey(), entry.getValue());
                }
            }
            
            // AI 분석 요청
            AIRequest<FraudAnalysisContext> aiRequest = FraudAnalysisRequest.create(context, "fraudAnalysis");
            
            Mono<FraudAnalysisResponse> responseMono = aINativeProcessor.process(aiRequest, FraudAnalysisResponse.class);
            FraudAnalysisResponse response = responseMono
                    .timeout(AI_TIMEOUT)
                    .doOnError(error -> log.error("사기 분석 오류", error))
                    .block();
            
            if (response != null) {
                double fraudScore = response.getFraudProbability();
                boolean isSafe = fraudScore < FRAUD_THRESHOLD;
                
                log.info("사기 거래 분석 완료 - userId: {}, fraudScore: {}, safe: {}, reason: {}",
                        userId, fraudScore, isSafe, response.getReason());
                
                // 감사 로그 기록
                recordAuditLog("FRAUD_ANALYSIS", userId, transaction, fraudScore, isSafe);
                
                return isSafe;
            }
            
            log.error("사기 분석 응답 없음");
            return false;
            
        } catch (Exception e) {
            log.error("사기 거래 분석 실패 - userId: {}", userId, e);
            return false; // Fail-closed
        }
    }
    
    /**
     * 이상 행동 탐지 (실시간) - AI Native
     *
     * AI Native 방식: LLM이 직접 이상 행동을 판단
     * 규칙 기반 Strategy 제거됨
     *
     * @param operation 작업 정보
     * @return 정상 행동이면 true
     */
    public boolean detectAnomaly(String operation) {
        String userId = extractUserId();
        if (userId == null || operation == null) {
            log.warn("detectAnomaly: 필수 정보 누락");
            return false;
        }

        try {
            log.info("이상 행동 탐지 시작 (AI Native) - userId: {}, operation: {}", userId, operation);

            // AI Native: AICoreOperations를 통한 LLM 호출
            // 규칙 기반 Strategy(MITRE, NIST, CIS) 제거됨
            SecurityEvent event = createSecurityEvent(userId, operation);

            // RiskAssessmentContext로 AI 분석 요청
            RiskAssessmentContext riskContext = new RiskAssessmentContext();
            riskContext.setUserId(userId);
            riskContext.setActionType(operation);
            riskContext.setRemoteIp(getRemoteIp());

            Map<String, Object> eventMetadata = new HashMap<>();
            eventMetadata.put("eventType", event.getEventType());
            eventMetadata.put("timestamp", event.getTimestamp());
            riskContext.setEnvironmentAttributes(eventMetadata);

            AIRequest<RiskAssessmentContext> aiRequest = RiskAssessmentRequest.create(riskContext, "anomalyDetection");

            Mono<RiskAssessmentResponse> responseMono = aINativeProcessor.process(aiRequest, RiskAssessmentResponse.class);
            RiskAssessmentResponse response = responseMono
                    .timeout(AI_TIMEOUT)
                    .doOnError(error -> log.error("이상 탐지 AI 분석 오류", error))
                    .block();

            double riskScore = 0.0;
            boolean isNormal = true;

            if (response != null) {
                riskScore = response.riskScore();
                isNormal = riskScore < ANOMALY_THRESHOLD;
            }

            log.info("이상 행동 탐지 완료 (AI Native) - userId: {}, riskScore: {}, normal: {}",
                    userId, riskScore, isNormal);

            // 감사 로그 기록
            Map<String, Object> operationData = new HashMap<>();
            operationData.put("operation", operation);
            operationData.put("analysisType", "AI_NATIVE");
            recordAuditLog("ANOMALY_DETECTION", userId, operationData, riskScore, isNormal);

            return isNormal;

        } catch (Exception e) {
            log.error("이상 행동 탐지 실패 - userId: {}, operation: {}", userId, operation, e);
            return false;
        }
    }
    
    /**
     * 중요 작업 평가 (매우 높은 권한 필요)
     * 
     * @param context 작업 컨텍스트
     * @return 작업이 안전하면 true
     */
    public boolean evaluateCriticalOperation(Map<String, Object> context) {
        String userId = extractUserId();
        if (userId == null || context == null) {
            log.warn("evaluateCriticalOperation: 필수 정보 누락");
            return false;
        }
        
        try {
            log.warn("중요 작업 평가 시작 (높은 비용) - userId: {}, operation: {}", 
                    userId, context.get("operationType"));
            
            // RiskAssessmentContext 생성
            RiskAssessmentContext riskContext = new RiskAssessmentContext();
            riskContext.setUserId(userId);
            riskContext.setActionType(String.valueOf(context.get("operationType")));
            riskContext.setResourceIdentifier(String.valueOf(context.get("resourceId")));
            // Impact level not available in RiskAssessmentContext
            // Request time handled internally
            riskContext.setRemoteIp(getRemoteIp());
            
            // 추가 컨텍스트
            Map<String, Object> additionalContext = new HashMap<>();
            additionalContext.put("targetSystem", context.get("targetSystem"));
            additionalContext.put("dataClassification", context.get("dataClassification"));
            additionalContext.put("privilegeLevel", context.get("privilegeLevel"));
            riskContext.setEnvironmentAttributes(additionalContext);
            
            // AI 위험 평가 요청
            AIRequest<RiskAssessmentContext> aiRequest = RiskAssessmentRequest.create(riskContext, "criticalOperation");
            
            Mono<RiskAssessmentResponse> responseMono = aINativeProcessor.process(aiRequest, RiskAssessmentResponse.class);
            RiskAssessmentResponse response = responseMono
                    .timeout(CRITICAL_AI_TIMEOUT) // 중요 작업은 더 긴 타임아웃
                    .doOnError(error -> log.error("중요 작업 평가 오류", error))
                    .block();
            
            if (response != null) {
                double riskScore = response.riskScore();
                boolean isSafe = riskScore < CRITICAL_THRESHOLD;
                
                log.warn("중요 작업 평가 완료 - userId: {}, riskScore: {}, safe: {}, mitigation: {}",
                        userId, riskScore, isSafe, response.recommendation());
                
                // 감사 로그 기록 (중요!)
                recordAuditLog("CRITICAL_OPERATION", userId, context, riskScore, isSafe);
                
                // 위험한 경우 추가 알림
                if (!isSafe) {
                    sendSecurityAlert(userId, context, riskScore);
                }
                
                return isSafe;
            }
            
            log.error("중요 작업 평가 응답 없음");
            return false;
            
        } catch (Exception e) {
            log.error("중요 작업 평가 실패 - userId: {}", userId, e);
            return false;
        }
    }
    
    /**
     * 데이터 유출 위험 평가 - AI Native
     *
     * AI Native 방식: LLM이 직접 데이터 유출 위험을 판단
     * 규칙 기반 Strategy 제거됨
     *
     * @param dataAccess 데이터 접근 정보
     * @return 안전한 접근이면 true
     */
    public boolean evaluateDataExfiltration(Map<String, Object> dataAccess) {
        String userId = extractUserId();
        if (userId == null || dataAccess == null) {
            return false;
        }

        try {
            log.info("데이터 유출 위험 평가 (AI Native) - userId: {}, volume: {}",
                    userId, dataAccess.get("dataVolume"));

            // AI Native: 모든 데이터 접근에 대해 LLM 분석 수행
            RiskAssessmentContext riskContext = new RiskAssessmentContext();
            riskContext.setUserId(userId);
            riskContext.setActionType("DATA_EXFILTRATION_CHECK");
            riskContext.setRemoteIp(getRemoteIp());
            riskContext.setEnvironmentAttributes(dataAccess);

            AIRequest<RiskAssessmentContext> aiRequest = RiskAssessmentRequest.create(riskContext, "dataExfiltration");

            Mono<RiskAssessmentResponse> responseMono = aINativeProcessor.process(aiRequest, RiskAssessmentResponse.class);
            RiskAssessmentResponse response = responseMono
                    .timeout(AI_TIMEOUT)
                    .doOnError(error -> log.error("데이터 유출 AI 분석 오류", error))
                    .block();

            if (response != null) {
                boolean isSafe = response.riskScore() < 0.5;

                log.info("데이터 유출 평가 완료 (AI Native) - userId: {}, risk: {}, safe: {}",
                        userId, response.riskScore(), isSafe);

                return isSafe;
            }

            return true; // AI 분석 실패 시 기본 허용 (fail-open)

        } catch (Exception e) {
            log.error("데이터 유출 평가 실패", e);
            return false;
        }
    }
    
    /**
     * 권한 상승 요청 평가 - AI Native
     *
     * AI Native 방식: LLM이 직접 권한 상승 위험을 판단
     * 규칙 기반 Strategy 제거됨
     *
     * @param requestedRole 요청된 권한
     * @return 권한 부여가 안전하면 true
     */
    public boolean evaluatePrivilegeEscalation(String requestedRole) {
        String userId = extractUserId();
        if (userId == null || requestedRole == null) {
            return false;
        }

        try {
            log.info("권한 상승 평가 (AI Native) - userId: {}, requestedRole: {}", userId, requestedRole);

            // AI Native: 모든 권한 상승 요청에 대해 LLM 분석 수행
            RiskAssessmentContext riskContext = new RiskAssessmentContext();
            riskContext.setUserId(userId);
            riskContext.setActionType("PRIVILEGE_ESCALATION");
            riskContext.setRemoteIp(getRemoteIp());

            Map<String, Object> escalationContext = new HashMap<>();
            escalationContext.put("requestedRole", requestedRole);
            escalationContext.put("isHighRisk", requestedRole.contains("ADMIN") ||
                                               requestedRole.contains("ROOT") ||
                                               requestedRole.contains("SYSTEM"));
            riskContext.setEnvironmentAttributes(escalationContext);

            AIRequest<RiskAssessmentContext> aiRequest = RiskAssessmentRequest.create(riskContext, "privilegeEscalation");

            Mono<RiskAssessmentResponse> responseMono = aINativeProcessor.process(aiRequest, RiskAssessmentResponse.class);
            RiskAssessmentResponse response = responseMono
                    .timeout(CRITICAL_AI_TIMEOUT) // 권한 상승은 중요 작업
                    .doOnError(error -> log.error("권한 상승 AI 분석 오류", error))
                    .block();

            if (response != null) {
                boolean isSafe = response.riskScore() < 0.6;

                log.warn("권한 상승 평가 완료 (AI Native) - userId: {}, riskScore: {}, safe: {}",
                        userId, response.riskScore(), isSafe);

                return isSafe;
            }

            return false; // AI 분석 실패 시 거부 (fail-closed for privilege escalation)

        } catch (Exception e) {
            log.error("권한 상승 평가 실패", e);
            return false;
        }
    }
    
    /**
     * SecurityEvent 생성 헬퍼
     */
    private SecurityEvent createSecurityEvent(String userId, String eventType) {
        SecurityEvent event = new SecurityEvent();
        event.setEventId(java.util.UUID.randomUUID().toString());
        event.setEventType(SecurityEvent.EventType.valueOf(eventType));
        event.setUserId(userId);
        event.setUserName(userId);
        event.setTimestamp(LocalDateTime.now());
        event.setSourceIp(getRemoteIp());
        event.setMetadata(new HashMap<>());
        return event;
    }
    
    /**
     * 사용자 ID 추출
     */
    private String extractUserId() {
        Authentication authentication = getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        
        Object principal = authentication.getPrincipal();
        if (principal instanceof UserDto) {
            UserDto userDto = (UserDto) principal;
            return userDto.getId() != null ? userDto.getId().toString() : userDto.getUsername();
        } else if (principal instanceof String) {
            return (String) principal;
        }
        
        return null;
    }
    
    /**
     * 감사 로그 기록
     */
    private void recordAuditLog(String action, String userId, Map<String, Object> context, 
                                double riskScore, boolean allowed) {
        try {
            io.contexa.contexacommon.entity.AuditLog log = io.contexa.contexacommon.entity.AuditLog.builder()
                .action(action)
                .principalName(userId)
                .clientIp(getRemoteIp())
                .decision(allowed ? "ALLOW" : "DENY")
                .reason("Risk Score: " + riskScore)
                .resourceIdentifier(context.toString())
                .status(allowed ? "SUCCESS" : "DENIED")
                .build();
            
            auditLogRepository.save(log);
        } catch (Exception e) {
            log.error("감사 로그 기록 실패", e);
        }
    }
    
    /**
     * 보안 알림 전송
     */
    private void sendSecurityAlert(String userId, Map<String, Object> context, double riskScore) {
        log.error("🚨 보안 알림: 고위험 작업 시도 - userId: {}, risk: {}, context: {}", 
                 userId, riskScore, context);
        // TODO: 실제 알림 시스템 연동
    }
    
    @Override
    protected String getRemoteIp() {
        if (authorizationContext != null && authorizationContext.environment() != null) {
            HttpServletRequest request = authorizationContext.environment().request();
            if (request != null) {
                String xForwardedFor = request.getHeader("X-Forwarded-For");
                if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                    return xForwardedFor.split(",")[0].trim();
                }
                return request.getRemoteAddr();
            }
            return authorizationContext.environment().remoteIp();
        }
        return "unknown";
    }
    
    @Override
    protected String getCurrentActivityDescription() {
        if (authorizationContext != null) {
            String action = authorizationContext.action();
            if (authorizationContext.resource() != null) {
                String resourceId = authorizationContext.resource().identifier();
                return String.format("%s %s", action, resourceId);
            }
            return action;
        }
        return "realtime AI analysis";
    }
    
    @Override
    protected ContextExtractionResult extractCurrentContext() {
        String remoteIp = getRemoteIp();
        String userAgent = "";
        String resourceIdentifier = "";
        String actionType = "";
        
        if (authorizationContext != null) {
            if (authorizationContext.environment() != null && authorizationContext.environment().request() != null) {
                userAgent = authorizationContext.environment().request().getHeader("User-Agent");
            }
            if (authorizationContext.resource() != null) {
                resourceIdentifier = authorizationContext.resource().identifier();
            }
            actionType = authorizationContext.action();
        }
        
        return new ContextExtractionResult(
            remoteIp, userAgent, resourceIdentifier, actionType);
    }
    
    @Override
    protected String calculateContextHash() {
        StringBuilder sb = new StringBuilder();
        if (authorizationContext != null) {
            if (authorizationContext.resource() != null) {
                sb.append(authorizationContext.resource().identifier());
            }
            sb.append(authorizationContext.action());
            if (authorizationContext.subjectEntity() != null) {
                sb.append(authorizationContext.subjectEntity().getId());
            }
        }
        sb.append(System.currentTimeMillis());
        return Integer.toHexString(sb.toString().hashCode());
    }
    
    // Inner classes for missing domain objects
    private static class FraudAnalysisContext extends io.contexa.contexacommon.domain.context.DomainContext {
        private String transactionId;
        private Double amount;
        private String currency;
        private String merchant;
        private LocalDateTime timestamp;
        private String sourceIp;
        private String deviceId;
        
        public FraudAnalysisContext() {
            super();
        }
        
        @Override
        public String getDomainType() {
            return "FRAUD_ANALYSIS";
        }
        
        @Override
        public int getPriorityLevel() {
            return 9; // High priority for fraud detection
        }
        
        // Getters and setters
        public void setTransactionId(String transactionId) { this.transactionId = transactionId; }
        public void setAmount(Double amount) { this.amount = amount; }
        public void setCurrency(String currency) { this.currency = currency; }
        public void setMerchant(String merchant) { this.merchant = merchant; }
        public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
        public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
        public void setDeviceId(String deviceId) { this.deviceId = deviceId; }
    }
    
    private static class FraudAnalysisRequest {
        public static AIRequest<FraudAnalysisContext> create(FraudAnalysisContext context, String type) {
            // AIRequest 생성자를 사용하여 요청 생성
            return new AIRequest<FraudAnalysisContext>(context, "fraudAnalysis", 
                AIRequest.RequestPriority.HIGH,
                AIRequest.RequestType.STANDARD);
        }
    }
    
    private static class FraudAnalysisResponse {
        private boolean isFraud;
        private double riskScore;
        private String reason;
        
        public boolean isFraud() { return isFraud; }
        public double getRiskScore() { return riskScore; }
        public String getReason() { return reason; }
        public double getFraudProbability() { return riskScore; } // Added for compatibility
    }
    
}