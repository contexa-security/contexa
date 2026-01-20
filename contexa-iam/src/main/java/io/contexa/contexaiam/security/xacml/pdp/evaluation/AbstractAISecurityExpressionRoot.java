package io.contexa.contexaiam.security.xacml.pdp.evaluation;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacommon.domain.TrustAssessment;
import io.contexa.contexacommon.domain.context.BehavioralAnalysisContext;
import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.BehavioralAnalysisRequest;
import io.contexa.contexacommon.domain.request.RiskAssessmentRequest;
import io.contexa.contexacommon.domain.response.BehavioralAnalysisResponse;
import io.contexa.contexacommon.domain.response.RiskAssessmentResponse;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexacommon.enums.SecurityLevel;
import io.contexa.contexacommon.dto.UserDto;
import io.contexa.contexaiam.security.xacml.pip.attribute.AttributeInformationPoint;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@Slf4j
public abstract class AbstractAISecurityExpressionRoot extends SecurityExpressionRoot {

    protected final AttributeInformationPoint attributePIP;
    protected final AICoreOperations aINativeProcessor;
    protected final AuthorizationContext authorizationContext;
    protected final AuditLogRepository auditLogRepository;
    
    
    protected TrustAssessment cachedAIAssessment;
    protected String lastAssessmentContextHash;

    protected AbstractAISecurityExpressionRoot(Authentication authentication,
                                             AttributeInformationPoint attributePIP,
                                               AICoreOperations aINativeProcessor,
                                             AuthorizationContext authorizationContext,
                                             AuditLogRepository auditLogRepository) {
        super(authentication);
        this.attributePIP = attributePIP;
        this.aINativeProcessor = aINativeProcessor;
        this.authorizationContext = authorizationContext;
        this.auditLogRepository = auditLogRepository;
        
        log.debug("AbstractAISecurityExpressionRoot 초기화 완료");
    }

    
    protected String getRemoteIp() {
        if (authorizationContext != null && authorizationContext.environment() != null) {
            jakarta.servlet.http.HttpServletRequest request = authorizationContext.environment().request();
            if (request != null) {
                
                String xForwardedFor = request.getHeader("X-Forwarded-For");
                if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                    return xForwardedFor.split(",")[0].trim();
                }

                
                String xRealIp = request.getHeader("X-Real-IP");
                if (xRealIp != null && !xRealIp.isEmpty()) {
                    return xRealIp;
                }

                return request.getRemoteAddr();
            }
            return authorizationContext.environment().remoteIp();
        }
        return "unknown";
    }

    
    protected String extractUserId() {
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

    
    protected abstract String getCurrentActivityDescription();

    
    public boolean hasSafeBehavior(double safeThresholdScore) {
        Authentication authentication = getAuthentication();
        if (authentication == null) {
            return false;
        }
        UserDto userDto = (UserDto) authentication.getPrincipal();
        String userId = userDto.getUsername();
        String remoteIp = getRemoteIp();
        String currentActivity = getCurrentActivityDescription();

        
        if (userId == null || remoteIp == null || currentActivity == null) {
            log.warn("hasSafeBehavior check failed: Missing required context. userId={}, remoteIp={}, activity={}", userId, remoteIp, currentActivity);
            return false;
        }

        BehavioralAnalysisContext context = new BehavioralAnalysisContext();
        context.setUserId(userId);
        context.setOrganizationId(userDto.getUsername());
        context.setCurrentActivity(currentActivity);
        context.setRemoteIp(remoteIp);

        AIRequest<BehavioralAnalysisContext> aiRequest = BehavioralAnalysisRequest.create(context, "behavioralAnalysis");
        try {
            log.debug("Initiating hasSafeBehavior check for user '{}'. Threshold: {}", userId, safeThresholdScore);
            Mono<BehavioralAnalysisResponse> aiResultMono = aINativeProcessor.process(aiRequest, BehavioralAnalysisResponse.class);
            BehavioralAnalysisResponse response = aiResultMono
                    .timeout(Duration.ofSeconds(180))
                    .doOnError(error -> log.error("[{}] AI 평가 오류: {}", error.getMessage(), error))
                    .block();

            if (response instanceof BehavioralAnalysisResponse analysisResponse) {
                double riskScore = analysisResponse.getBehavioralRiskScore();
                boolean isSafe = riskScore <= safeThresholdScore;
                log.info("Behavioral analysis completed for user '{}'. Risk Score: {}. Threshold: {}. Access granted: {}",
                        userId, riskScore, safeThresholdScore, isSafe);
                return isSafe;
            } else {
                log.warn("hasSafeBehavior check failed for user '{}': AI analysis returned an unexpected response type or failed parsing.", userId);
                return false; 
            }
        } catch (Exception e) {
            log.error("hasSafeBehavior check failed for user '{}' due to an exception during AI processing.", userId, e);
            return false; 
        }
    }

    private BehavioralAnalysisResponse parseResponse(String json) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.readValue(json, BehavioralAnalysisResponse.class);
        } catch (Exception e) {
            
            return null;
        }
    }

    
    public TrustAssessment assessContext() {
        try {
            
            String currentContextHash = calculateContextHash();
            
            
            if (cachedAIAssessment != null && currentContextHash.equals(lastAssessmentContextHash)) {
                log.debug("AI 평가 캐시 재사용 - Hash: {}", currentContextHash);
                return cachedAIAssessment;
            }

            log.debug("AI 신뢰도 평가 시작 - 새로운 컨텍스트");
            
            
            ContextExtractionResult extractedContext = extractCurrentContext();
            
            
            double trustScore = performAdvancedAIRiskAssessment(
                extractedContext.remoteIp,
                extractedContext.userAgent,
                extractedContext.resourceIdentifier,
                extractedContext.actionType
            );
            
            
            this.cachedAIAssessment = createTrustAssessment(
                trustScore, 
                extractedContext.remoteIp, 
                extractedContext.resourceIdentifier, 
                extractedContext.actionType
            );
            
            this.lastAssessmentContextHash = currentContextHash;
            
            
            this.authorizationContext.attributes().put("ai_assessment", this.cachedAIAssessment);
            
            log.info("AI 신뢰도 평가 완료 - 점수: {}, 위험태그: {}", 
                     this.cachedAIAssessment.score(), this.cachedAIAssessment.riskTags());
            
            return this.cachedAIAssessment;
            
        } catch (Exception e) {
            log.error("AI 신뢰도 평가 실패: {}", e.getMessage(), e);
            
            
            this.cachedAIAssessment = createFallbackTrustAssessment();
            this.authorizationContext.attributes().put("ai_assessment", this.cachedAIAssessment);
            
            return this.cachedAIAssessment;
        }
    }

    
    public Object getAttribute(String key) {
        
        if (authorizationContext.attributes().containsKey(key)) {
            return authorizationContext.attributes().get(key);
        }
        
        
        try {
            Map<String, Object> fetchedAttributes = attributePIP.getAttributes(authorizationContext);
            authorizationContext.attributes().putAll(fetchedAttributes);
            
            Object value = authorizationContext.attributes().get(key);
            log.debug("속성 조회 - Key: {}, Value: {}", key, value);
            
            return value;
            
        } catch (Exception e) {
            log.warn("속성 조회 실패 - Key: {}, Error: {}", key, e.getMessage());
            return null;
        }
    }

    
    protected abstract ContextExtractionResult extractCurrentContext();
    
    
    protected abstract String calculateContextHash();

    

    protected double performAdvancedAIRiskAssessment(String remoteIp, String userAgent, 
                                                   String resourceIdentifier, String actionType) {
        long assessmentStart = System.currentTimeMillis();
        String assessmentId = "AI_EVAL_" + System.currentTimeMillis();
        
        log.debug("[{}] AI 위험 평가 시작 - IP: {}, Resource: {}", assessmentId, remoteIp, resourceIdentifier);
        
        try {
            
            RiskAssessmentContext context = buildComprehensiveRiskContext(
                remoteIp, userAgent, resourceIdentifier, actionType, assessmentId);
            
            
            RiskAssessmentResponse aiResponse = executeAIRiskAssessment(context, assessmentId);
            
            
            double finalTrustScore = integrateAIWithBusinessRules(aiResponse, context, assessmentId);
            
            
            recordAIAssessmentAudit(context, aiResponse, finalTrustScore, assessmentId);
            
            long processingTime = System.currentTimeMillis() - assessmentStart;
            log.debug("[{}] AI 평가 완료 - 신뢰도: {}, 처리시간: {}ms",
                       assessmentId, finalTrustScore, processingTime);
            
            return finalTrustScore;
            
        } catch (Exception e) {
            log.error("[{}] AI 위험 평가 실패: {}", assessmentId, e.getMessage(), e);
            return applyFailsafePolicy(remoteIp, resourceIdentifier, e);
        }
    }

    private RiskAssessmentContext buildComprehensiveRiskContext(String remoteIp, String userAgent,
                                                                String resourceIdentifier, String actionType,
                                                                String assessmentId) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            String userId = auth != null ? auth.getName() : "anonymous";
            
            log.debug("[{}] 컨텍스트 구성 - User: {}", assessmentId, userId);
            
            RiskAssessmentContext context = new RiskAssessmentContext(
                userId, generateSessionId(), SecurityLevel.HIGH, AuditRequirement.REQUIRED);
            
            
            context.setResourceIdentifier(resourceIdentifier);
            context.setActionType(actionType);
            context.setRemoteIp(remoteIp);
            context.setUserAgent(userAgent);
            context.setLocation(determineGeographicLocation(remoteIp));
            
            
            if (auth != null && auth.getAuthorities() != null) {
                List<String> roles = auth.getAuthorities().stream()
                    .map(authority -> authority.getAuthority())
                    .collect(Collectors.toList());
                context.setUserRoles(roles);
            }
            
            
            enrichContextWithEnvironmentalFactors(context, remoteIp, userAgent, assessmentId);
            
            return context;
            
        } catch (Exception e) {
            log.error("[{}] 컨텍스트 구성 실패: {}", assessmentId, e.getMessage(), e);
            throw new RuntimeException("Risk context 구성 실패", e);
        }
    }

    private RiskAssessmentResponse executeAIRiskAssessment(RiskAssessmentContext context, String assessmentId) {
        try {
            log.debug("[{}] AI 위험 평가 실행", assessmentId);
            
            RiskAssessmentRequest request = RiskAssessmentRequest.create(context, "riskAssessment");

            Mono<RiskAssessmentResponse> aiResultMono = aINativeProcessor.process(request, RiskAssessmentResponse.class);
            
            RiskAssessmentResponse aiResponse = aiResultMono
                .timeout(Duration.ofSeconds(120))
                .doOnError(error -> log.error("[{}] AI 평가 오류: {}", assessmentId, error.toString()))
                .onErrorReturn(createEmergencyFallbackResponse(context, assessmentId))
                .block(); 

            assert aiResponse != null;
            log.info("[{}] AI 평가 성공 - 위험점수: {}", assessmentId, aiResponse.riskScore());
            return aiResponse;
            
        } catch (Exception e) {
            log.error("[{}] AI 평가 실행 실패: {}", assessmentId, e.getMessage(), e);
            return createEmergencyFallbackResponse(context, assessmentId);
        }
    }

    private double integrateAIWithBusinessRules(RiskAssessmentResponse aiResponse, 
                                              RiskAssessmentContext context, String assessmentId) {
        try {
            double aiTrustScore = aiResponse.trustScore();
            log.debug("[{}] AI 신뢰도: {}", assessmentId, aiTrustScore);
            
            
            double businessWeight = calculateBusinessWeight(context);
            double complianceWeight = calculateComplianceWeight(context);
            
            
            double finalScore = aiTrustScore * 0.7 + businessWeight * 0.2 + complianceWeight * 0.1;
            
            
            if (aiResponse.riskScore() > 0.8) {
                finalScore = Math.min(finalScore, 0.4); 
            }
            
            return Math.max(0.0, Math.min(1.0, finalScore));
            
        } catch (Exception e) {
            log.error("[{}] 점수 통합 실패: {}", assessmentId, e.getMessage());
            return 0.3; 
        }
    }

    
    private void recordAIAssessmentAudit(RiskAssessmentContext context, RiskAssessmentResponse aiResponse,
                                       double finalScore, String assessmentId) {
        try {
            
            if (TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
                log.debug("[{}] Read-only 트랜잭션으로 인해 감사 로그 기록 건너뜀", assessmentId);
                return;
            }
            
            Map<String, Object> auditData = new HashMap<>();
            auditData.put("assessmentId", assessmentId);
            auditData.put("userId", context.getUserId());
            auditData.put("resourceId", context.getResourceIdentifier());
            auditData.put("aiRiskScore", aiResponse.riskScore());
            auditData.put("finalTrustScore", finalScore);
            auditData.put("timestamp", LocalDateTime.now());
            
            auditLogRepository.save(createAuditLogEntry(auditData));
            log.debug("[{}] 감사 로그 기록 완료", assessmentId);
            
        } catch (Exception e) {
            log.error("[{}] 감사 로그 기록 실패: {}", assessmentId, e.getMessage());
            
        }
    }

    

    private void enrichContextWithEnvironmentalFactors(RiskAssessmentContext context, String remoteIp,
                                                       String userAgent, String assessmentId) {
        try {
            LocalDateTime now = LocalDateTime.now();
            
            
            context.withEnvironmentAttribute("isBusinessHours", isBusinessHours(now));
            context.withEnvironmentAttribute("isWeekend", now.getDayOfWeek().getValue() >= 6);
            context.withEnvironmentAttribute("accessHour", now.getHour());
            context.withEnvironmentAttribute("isInternalNetwork", isInternalIP(remoteIp));
            context.withEnvironmentAttribute("deviceType", determineDeviceType(userAgent));
            
            
            if (context.getBehaviorMetrics() != null) {
                context.getBehaviorMetrics().put("mfaEnabled", "Unknown"); 
                context.getBehaviorMetrics().put("lastLoginHours", 24); 
                context.getBehaviorMetrics().put("sessionCount", 1); 
                context.getBehaviorMetrics().put("averageSessionDuration", 30); 
                context.getBehaviorMetrics().put("deviceTrust", isInternalIP(remoteIp) ? "High" : "Medium");
                context.getBehaviorMetrics().put("locationConsistency", "Unknown");
                context.getBehaviorMetrics().put("accessPatternNormality", 0.8); 
            }
            
        } catch (Exception e) {
            log.warn("[{}] 환경 요인 수집 실패: {}", assessmentId, e.getMessage());
        }
    }

    private TrustAssessment createTrustAssessment(double trustScore, String remoteIp, 
                                                String resourceIdentifier, String actionType) {
        List<String> riskTags = determineRiskTags(trustScore, remoteIp, resourceIdentifier);
        String summary = String.format("AI 신뢰도: %.2f, 액션: %s", trustScore, actionType);
        return new TrustAssessment(trustScore, riskTags, summary);
    }

    private TrustAssessment createFallbackTrustAssessment() {
        return new TrustAssessment(0.3, List.of("EVALUATION_FAILED", "LOW_TRUST"), "AI 평가 실패 - 보수적 정책 적용");
    }

    private RiskAssessmentResponse createEmergencyFallbackResponse(RiskAssessmentContext context, String assessmentId) {
        return RiskAssessmentResponse.defaultSafe(assessmentId);
    }

    private AuditLog createAuditLogEntry(Map<String, Object> auditData) {
        return AuditLog.builder()
            .principalName((String) auditData.get("userId"))
            .resourceIdentifier((String) auditData.get("resourceId"))
            .action("AI_ASSESSMENT")
            .decision("EVALUATED")
            .reason("AI 기반 신뢰도 평가")
            .details(auditData.toString())
            .build();
    }

    

    private double calculateBusinessWeight(RiskAssessmentContext context) {
        double weight = 1.0;
        
        if (context.getEnvironmentAttributes() != null) {
            Boolean isBusinessHours = (Boolean) context.getEnvironmentAttributes().get("isBusinessHours");
            if (Boolean.FALSE.equals(isBusinessHours)) weight -= 0.2;
            
            Boolean isInternal = (Boolean) context.getEnvironmentAttributes().get("isInternalNetwork");
            if (Boolean.TRUE.equals(isInternal)) weight += 0.1;
        }
        
        return Math.max(0.0, Math.min(1.0, weight));
    }

    private double calculateComplianceWeight(RiskAssessmentContext context) {
        double weight = 1.0;
        
        String resourceId = context.getResourceIdentifier();
        if (resourceId != null && (resourceId.contains("admin") || resourceId.contains("sensitive"))) {
            weight -= 0.3;
        }
        
        return Math.max(0.0, Math.min(1.0, weight));
    }

    private List<String> determineRiskTags(double trustScore, String remoteIp, String resourceIdentifier) {
        List<String> tags = new java.util.ArrayList<>();
        
        if (trustScore < 0.3) tags.add("HIGH_RISK");
        else if (trustScore < 0.6) tags.add("MEDIUM_RISK");
        else tags.add("LOW_RISK");
        
        if (!isInternalIP(remoteIp)) tags.add("EXTERNAL_ACCESS");
        if (resourceIdentifier != null && resourceIdentifier.contains("admin")) tags.add("ADMIN_RESOURCE");
        
        return tags;
    }

    private boolean isBusinessHours(LocalDateTime time) {
        int hour = time.getHour();
        int dayOfWeek = time.getDayOfWeek().getValue();
        return dayOfWeek <= 5 && hour >= 9 && hour <= 18;
    }

    private boolean isInternalIP(String ip) {
        if (ip == null) return false;
        return ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.16.") || ip.equals("127.0.0.1");
    }

    private String determineGeographicLocation(String ip) {
        return isInternalIP(ip) ? "Internal" : "External";
    }

    private String determineDeviceType(String userAgent) {
        if (userAgent == null) return "unknown";
        if (userAgent.toLowerCase().contains("mobile")) return "mobile";
        if (userAgent.toLowerCase().contains("tablet")) return "tablet";
        return "desktop";
    }

    private String generateSessionId() {
        return "ai-session-" + System.currentTimeMillis();
    }

    private double applyFailsafePolicy(String remoteIp, String resourceIdentifier, Exception error) {
        log.warn("보수적 정책 적용 - IP: {}, Resource: {}, 원인: {}", 
                   remoteIp, resourceIdentifier, error.getMessage());
        return isInternalIP(remoteIp) ? 0.6 : 0.3;
    }

    
    
    

    
    protected void storeActionAsTrustAssessment(String action) {
        if (authorizationContext == null) {
            log.debug("AuthorizationContext가 null - TrustAssessment 저장 생략");
            return;
        }

        
        if (authorizationContext.attributes().containsKey("ai_assessment")) {
            log.trace("TrustAssessment가 이미 저장됨 - 중복 저장 생략");
            return;
        }

        
        double score = switch (action != null ? action.toUpperCase() : "PENDING_ANALYSIS") {
            case "ALLOW" -> 1.0;
            case "CHALLENGE" -> 0.5;
            case "ESCALATE" -> 0.3;
            case "BLOCK" -> 0.0;
            default -> 0.5; 
        };

        List<String> riskTags = List.of("LLM_ACTION", action != null ? action : "PENDING_ANALYSIS");
        String summary = "Redis LLM Action: " + (action != null ? action : "PENDING_ANALYSIS");

        TrustAssessment assessment = new TrustAssessment(score, riskTags, summary);
        authorizationContext.attributes().put("ai_assessment", assessment);

        log.debug("Action 기반 TrustAssessment 저장 완료 - action: {}, score: {}", action, score);
    }

    
    protected abstract String getCurrentAction();

    
    public boolean isAllowed() {
        return hasAction("ALLOW");
    }

    
    public boolean isBlocked() {
        return hasAction("BLOCK");
    }

    
    public boolean needsChallenge() {
        return hasAction("CHALLENGE");
    }

    
    public boolean needsEscalation() {
        return hasAction("ESCALATE");
    }

    
    public boolean isPendingAnalysis() {
        String action = getCurrentAction();

        
        storeActionAsTrustAssessment(action);

        return action == null || action.isEmpty() || "PENDING_ANALYSIS".equalsIgnoreCase(action);
    }

    
    public boolean hasAction(String expectedAction) {
        String action = getCurrentAction();

        
        storeActionAsTrustAssessment(action);

        if (action == null || action.isEmpty()) {
            return false;
        }
        return expectedAction.equalsIgnoreCase(action);
    }

    
    public boolean hasActionIn(String... allowedActions) {
        String action = getCurrentAction();

        
        storeActionAsTrustAssessment(action);

        if (action == null || action.isEmpty()) {
            return false;
        }
        return Arrays.stream(allowedActions)
            .anyMatch(a -> a.equalsIgnoreCase(action));
    }

    
    public boolean hasSafeBehaviorWithAction(double threshold) {
        return hasSafeBehavior(threshold) && !isBlocked();
    }

    
    public boolean assessContextWithAction() {
        TrustAssessment assessment = assessContext();
        if (assessment == null || assessment.score() < 0.5) {
            return false;
        }
        return hasAction("ALLOW");
    }

    
    
    

    
    public boolean isAnalysisComplete() {
        String action = getCurrentAction();
        return action != null
            && !action.isEmpty()
            && !"PENDING_ANALYSIS".equalsIgnoreCase(action);
    }

    
    public boolean requiresAnalysis() {
        boolean complete = isAnalysisComplete();
        if (!complete) {
            log.warn("분석 필수 리소스 접근 시도 - 분석 미완료 상태");
        }
        return complete;
    }

    
    public boolean requiresAnalysisWithAction(String... allowedActions) {
        if (!isAnalysisComplete()) {
            log.warn("분석 필수 리소스 접근 시도 - 분석 미완료 상태");
            return false;
        }
        boolean hasAllowedAction = hasActionIn(allowedActions);
        if (!hasAllowedAction) {
            log.warn("분석 완료 but 허용되지 않은 action - current: {}, allowed: {}",
                getCurrentAction(), Arrays.toString(allowedActions));
        }
        return hasAllowedAction;
    }

    
    public boolean hasActionOrDefault(String defaultAction, String... allowedActions) {
        String action = getCurrentAction();
        if (action == null || action.isEmpty() || "PENDING_ANALYSIS".equalsIgnoreCase(action)) {
            
            action = defaultAction;
            log.debug("분석 미완료 - 기본 action 사용: {}", defaultAction);
        }

        
        storeActionAsTrustAssessment(action);

        final String finalAction = action;
        return Arrays.stream(allowedActions)
            .anyMatch(a -> a.equalsIgnoreCase(finalAction));
    }

    
    protected static class ContextExtractionResult {
        public final String remoteIp;
        public final String userAgent;
        public final String resourceIdentifier;
        public final String actionType;

        public ContextExtractionResult(String remoteIp, String userAgent,
                                     String resourceIdentifier, String actionType) {
            this.remoteIp = remoteIp;
            this.userAgent = userAgent;
            this.resourceIdentifier = resourceIdentifier;
            this.actionType = actionType;
        }
    }

    
    
    

    
    protected String getActionFromRedisHash(String userId, String redisKey,
                                            org.springframework.data.redis.core.StringRedisTemplate stringRedisTemplate) {
        if (userId == null || redisKey == null || stringRedisTemplate == null) {
            log.debug("getActionFromRedisHash: 필수 파라미터 누락 - PENDING_ANALYSIS 반환");
            return "PENDING_ANALYSIS";
        }

        try {
            Object actionValue = stringRedisTemplate.opsForHash().get(redisKey, "action");

            if (actionValue != null) {
                String action = actionValue.toString();
                log.debug("getActionFromRedisHash: Redis 조회 성공 - userId: {}, action: {}", userId, action);
                return action;
            } else {
                log.debug("getActionFromRedisHash: Redis에 action 없음 - userId: {}, PENDING_ANALYSIS 반환", userId);
                return "PENDING_ANALYSIS";
            }
        } catch (Exception e) {
            log.error("getActionFromRedisHash: Redis 조회 실패 - userId: {}, PENDING_ANALYSIS 반환", userId, e);
            return "PENDING_ANALYSIS";
        }
    }

    
    protected ContextExtractionResult extractContextFromAuthorizationContext() {
        String remoteIp = getRemoteIp();
        String userAgent = "";
        String resourceIdentifier = "";
        String actionType = "";

        if (authorizationContext != null) {
            if (authorizationContext.environment() != null && authorizationContext.environment().request() != null) {
                userAgent = authorizationContext.environment().request().getHeader("User-Agent");
                if (userAgent == null) {
                    userAgent = "";
                }
            }
            if (authorizationContext.resource() != null) {
                resourceIdentifier = authorizationContext.resource().identifier();
            }
            actionType = authorizationContext.action();
        }

        return new ContextExtractionResult(remoteIp, userAgent, resourceIdentifier, actionType);
    }

    
    protected String calculateContextHashFromAuthorizationContext() {
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
} 