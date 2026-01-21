package io.contexa.contexaiam.security.xacml.pdp.evaluation.method;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;

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
import org.springframework.data.redis.core.StringRedisTemplate;
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

@Slf4j
public class RealtimeAISecurityExpressionRoot extends AbstractAISecurityExpressionRoot {

    private static final Duration AI_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration CRITICAL_AI_TIMEOUT = Duration.ofSeconds(60);

    private static final double FRAUD_THRESHOLD = 0.7;
    private static final double ANOMALY_THRESHOLD = 0.6;
    private static final double CRITICAL_THRESHOLD = 0.8;

    private final StringRedisTemplate stringRedisTemplate;

    public RealtimeAISecurityExpressionRoot(Authentication authentication,
                                            AttributeInformationPoint attributePIP,
                                            AICoreOperations aINativeProcessor,
                                            AuthorizationContext authorizationContext,
                                            AuditLogRepository auditLogRepository,
                                            StringRedisTemplate stringRedisTemplate) {
        super(authentication, attributePIP, aINativeProcessor, authorizationContext, auditLogRepository);
        this.stringRedisTemplate = stringRedisTemplate;
            }

    public RealtimeAISecurityExpressionRoot(Authentication authentication,
                                            AttributeInformationPoint attributePIP,
                                            AICoreOperations aINativeProcessor,
                                            AuthorizationContext authorizationContext,
                                            AuditLogRepository auditLogRepository) {
        super(authentication, attributePIP, aINativeProcessor, authorizationContext, auditLogRepository);
        this.stringRedisTemplate = null;
            }

    public boolean analyzeFraud(Map<String, Object> transaction) {
        if (transaction == null || transaction.isEmpty()) {
            log.warn("analyzeFraud: 거래 정보가 없음");
            return false; 
        }
        
        String userId = extractUserId();
        if (userId == null) {
            log.warn("analyzeFraud: 사용자 ID를 추출할 수 없음");
            return false;
        }
        
        try {

            FraudAnalysisContext context = new FraudAnalysisContext();
            context.setUserId(userId);
            context.setTransactionId(String.valueOf(transaction.get("id")));
            context.setAmount(Double.valueOf(String.valueOf(transaction.get("amount"))));
            context.setCurrency(String.valueOf(transaction.get("currency")));
            context.setMerchant(String.valueOf(transaction.get("merchant")));
            context.setTimestamp(LocalDateTime.now());
            context.setSourceIp(getRemoteIp());
            context.setDeviceId(String.valueOf(transaction.get("deviceId")));

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("transactionType", transaction.get("type"));
            metadata.put("paymentMethod", transaction.get("paymentMethod"));
            metadata.put("location", transaction.get("location"));
            
            if (metadata != null) {
                for (Map.Entry<String, Object> entry : metadata.entrySet()) {
                    context.addMetadata(entry.getKey(), entry.getValue());
                }
            }

            AIRequest<FraudAnalysisContext> aiRequest = FraudAnalysisRequest.create(context, "riskAssessment");
            
            Mono<FraudAnalysisResponse> responseMono = aINativeProcessor.process(aiRequest, FraudAnalysisResponse.class);
            FraudAnalysisResponse response = responseMono
                    .timeout(AI_TIMEOUT)
                    .doOnError(error -> log.error("사기 분석 오류", error))
                    .block();
            
            if (response != null) {
                double fraudScore = response.getFraudProbability();
                boolean isSafe = fraudScore < FRAUD_THRESHOLD;

                recordAuditLog("FRAUD_ANALYSIS", userId, transaction, fraudScore, isSafe);
                
                return isSafe;
            }
            
            log.error("사기 분석 응답 없음");
            return false;
            
        } catch (Exception e) {
            log.error("사기 거래 분석 실패 - userId: {}", userId, e);
            return false; 
        }
    }

    public boolean detectAnomaly(String operation) {
        String userId = extractUserId();
        if (userId == null || operation == null) {
            log.warn("detectAnomaly: 필수 정보 누락");
            return false;
        }

        try {

            SecurityEvent event = createSecurityEvent(userId, operation);

            RiskAssessmentContext riskContext = new RiskAssessmentContext();
            riskContext.setUserId(userId);
            riskContext.setActionType(operation);
            riskContext.setRemoteIp(getRemoteIp());

            Map<String, Object> eventMetadata = new HashMap<>();
            eventMetadata.put("severity", event.getSeverity());
            eventMetadata.put("timestamp", event.getTimestamp());
            riskContext.setEnvironmentAttributes(eventMetadata);

            AIRequest<RiskAssessmentContext> aiRequest = RiskAssessmentRequest.create(riskContext, "riskAssessment");

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

            String action = getCurrentAction();
            if ("BLOCK".equals(action)) {
                log.warn("detectAnomaly: LLM BLOCK action detected - userId: {}, operation: {}", userId, operation);
                isNormal = false;
            }

            Map<String, Object> operationData = new HashMap<>();
            operationData.put("operation", operation);
            operationData.put("analysisType", "AI_NATIVE");
            operationData.put("llmAction", action);
            recordAuditLog("ANOMALY_DETECTION", userId, operationData, riskScore, isNormal);

            return isNormal;

        } catch (Exception e) {
            log.error("이상 행동 탐지 실패 - userId: {}, operation: {}", userId, operation, e);
            return false;
        }
    }

    public boolean evaluateCriticalOperation(Map<String, Object> context) {
        String userId = extractUserId();
        if (userId == null || context == null) {
            log.warn("evaluateCriticalOperation: 필수 정보 누락");
            return false;
        }
        
        try {
            log.warn("중요 작업 평가 시작 (높은 비용) - userId: {}, operation: {}", 
                    userId, context.get("operationType"));

            RiskAssessmentContext riskContext = new RiskAssessmentContext();
            riskContext.setUserId(userId);
            riskContext.setActionType(String.valueOf(context.get("operationType")));
            riskContext.setResourceIdentifier(String.valueOf(context.get("resourceId")));

            riskContext.setRemoteIp(getRemoteIp());

            Map<String, Object> additionalContext = new HashMap<>();
            additionalContext.put("targetSystem", context.get("targetSystem"));
            additionalContext.put("dataClassification", context.get("dataClassification"));
            additionalContext.put("privilegeLevel", context.get("privilegeLevel"));
            riskContext.setEnvironmentAttributes(additionalContext);

            AIRequest<RiskAssessmentContext> aiRequest = RiskAssessmentRequest.create(riskContext, "riskAssessment");
            
            Mono<RiskAssessmentResponse> responseMono = aINativeProcessor.process(aiRequest, RiskAssessmentResponse.class);
            RiskAssessmentResponse response = responseMono
                    .timeout(CRITICAL_AI_TIMEOUT) 
                    .doOnError(error -> log.error("중요 작업 평가 오류", error))
                    .block();
            
            if (response != null) {
                double riskScore = response.riskScore();
                boolean isSafe = riskScore < CRITICAL_THRESHOLD;
                
                log.warn("중요 작업 평가 완료 - userId: {}, riskScore: {}, safe: {}, mitigation: {}",
                        userId, riskScore, isSafe, response.recommendation());

                recordAuditLog("CRITICAL_OPERATION", userId, context, riskScore, isSafe);

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

    public boolean evaluateDataExfiltration(Map<String, Object> dataAccess) {
        String userId = extractUserId();
        if (userId == null || dataAccess == null) {
            return false;
        }

        try {

            RiskAssessmentContext riskContext = new RiskAssessmentContext();
            riskContext.setUserId(userId);
            riskContext.setActionType("DATA_EXFILTRATION_CHECK");
            riskContext.setRemoteIp(getRemoteIp());
            riskContext.setEnvironmentAttributes(dataAccess);

            AIRequest<RiskAssessmentContext> aiRequest = RiskAssessmentRequest.create(riskContext, "riskAssessment");

            Mono<RiskAssessmentResponse> responseMono = aINativeProcessor.process(aiRequest, RiskAssessmentResponse.class);
            RiskAssessmentResponse response = responseMono
                    .timeout(AI_TIMEOUT)
                    .doOnError(error -> log.error("데이터 유출 AI 분석 오류", error))
                    .block();

            if (response != null) {
                boolean isSafe = response.riskScore() < 0.5;

                return isSafe;
            }

            log.warn("evaluateDataExfiltration: AI 분석 응답 없음 - userId: {}, Fail-Closed 적용", userId);
            return false; 

        } catch (Exception e) {
            log.error("데이터 유출 평가 실패 - userId: {}", userId, e);
            return false; 
        }
    }

    public boolean evaluatePrivilegeEscalation(String requestedRole) {
        String userId = extractUserId();
        if (userId == null || requestedRole == null) {
            return false;
        }

        try {

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

            AIRequest<RiskAssessmentContext> aiRequest = RiskAssessmentRequest.create(riskContext, "riskAssessment");

            Mono<RiskAssessmentResponse> responseMono = aINativeProcessor.process(aiRequest, RiskAssessmentResponse.class);
            RiskAssessmentResponse response = responseMono
                    .timeout(CRITICAL_AI_TIMEOUT) 
                    .doOnError(error -> log.error("권한 상승 AI 분석 오류", error))
                    .block();

            if (response != null) {
                boolean isSafe = response.riskScore() < 0.6;

                log.warn("권한 상승 평가 완료 (AI Native) - userId: {}, riskScore: {}, safe: {}",
                        userId, response.riskScore(), isSafe);

                return isSafe;
            }

            return false; 

        } catch (Exception e) {
            log.error("권한 상승 평가 실패", e);
            return false;
        }
    }

    private SecurityEvent createSecurityEvent(String userId, String eventType) {
        SecurityEvent event = new SecurityEvent();
        event.setEventId(java.util.UUID.randomUUID().toString());
        event.setSource(SecurityEvent.EventSource.IAM);
        event.setSeverity(SecurityEvent.Severity.MEDIUM);
        event.setUserId(userId);
        event.setUserName(userId);
        event.setTimestamp(LocalDateTime.now());
        event.setSourceIp(getRemoteIp());
        event.setMetadata(new HashMap<>());
        event.addMetadata("incidentType", eventType);
        return event;
    }

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

    private void sendSecurityAlert(String userId, Map<String, Object> context, double riskScore) {
        log.error("🚨 보안 알림: 고위험 작업 시도 - userId: {}, risk: {}, context: {}", 
                 userId, riskScore, context);
        
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
        
        return extractContextFromAuthorizationContext();
    }

    @Override
    protected String calculateContextHash() {
        
        return calculateContextHashFromAuthorizationContext();
    }

    @Override
    protected String getCurrentAction() {
        String userId = extractUserId();
        if (userId == null) {
            log.warn("getCurrentAction: 사용자 ID를 추출할 수 없음 - PENDING_ANALYSIS 반환");
            return "PENDING_ANALYSIS";
        }

        if (stringRedisTemplate == null) {
                        return "PENDING_ANALYSIS";
        }

        String redisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
        return getActionFromRedisHash(userId, redisKey, stringRedisTemplate);
    }

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
            return 9; 
        }

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
        public double getFraudProbability() { return riskScore; } 
    }
    
}