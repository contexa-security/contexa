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
import io.contexa.contexaiam.domain.dto.UserDto;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * AI 보안 표현식 루트 추상 클래스 (템플릿 메서드 패턴)
 * 
 * SecurityExpressionRoot를 상속하여 Spring Security의 표준 표현식 기능을 모두 제공하면서,
 * 공통 AI 진단 기능을 템플릿 메서드 패턴으로 구현합니다.
 * 
 * 템플릿 메서드: assessContext(), getAttribute() 등의 공통 기능
 * 추상 메서드: extractCurrentContext(), calculateContextHash() 등의 개별 구현
 */
@Slf4j
public abstract class AbstractAISecurityExpressionRoot extends SecurityExpressionRoot {

    protected final AttributeInformationPoint attributePIP;
    protected final AICoreOperations aINativeProcessor;
    protected final AuthorizationContext authorizationContext;
    protected final AuditLogRepository auditLogRepository;
    
    // AI 평가 결과 캐싱 - 하위 클래스에서 접근 가능하도록 protected
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

    /**
     * 요청의 원격 IP 주소를 반환합니다.
     * @return Remote IP Address
     */
    protected abstract String getRemoteIp();

    /**
     * 현재 보안 검사가 이루어지는 활동(Activity)에 대한 설명을 반환합니다.
     * (예: "HTTP GET /api/users/1", "Method execution: UserService.getUserDetails")
     * @return Activity Description
     */
    protected abstract String getCurrentActivityDescription();

    /**
     * [핵심 기능] 사용자의 현재 행동이 안전한지 AI를 통해 실시간으로 분석하고 판단합니다.
     * 이 메서드는 접근 제어 정책(Policy)의 SpEL 조건문에서 사용됩니다.
     * 예: hasRole('ADMIN') and hasSafeBehavior(20.0)
     *
     * @param safeThresholdScore 안전하다고 판단할 위험 점수 임계값 (이 값은 정책에서 직접 전달됩니다.)
     * @return AI가 분석한 행동 위험 점수가 임계값 이하이면 true, 아니면 false를 반환합니다.
     */
    public boolean hasSafeBehavior(double safeThresholdScore) {
        Authentication authentication = getAuthentication();
        if (authentication == null) {
            return false;
        }
        UserDto userDto = (UserDto) authentication.getPrincipal();
        String userId = userDto.getUsername();
        String remoteIp = getRemoteIp();
        String currentActivity = getCurrentActivityDescription();

        // 필수 컨텍스트 정보가 없으면 분석을 진행할 수 없으므로 실패 처리합니다.
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
                return false; // 분석 실패 시 안전을 위해 접근을 거부합니다 (Fail-Closed).
            }
        } catch (Exception e) {
            log.error("hasSafeBehavior check failed for user '{}' due to an exception during AI processing.", userId, e);
            return false; // 예외 발생 시 안전을 위해 접근을 거부합니다 (Fail-Closed).
        }
    }

    private BehavioralAnalysisResponse parseResponse(String json) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.readValue(json, BehavioralAnalysisResponse.class);
        } catch (Exception e) {
            // 로깅 필요
            return null;
        }
    }

    /**
     * [템플릿 메서드] AI 기반 컨텍스트 신뢰도 평가
     * 
     * 공통 AI 평가 로직을 제공하되, 컨텍스트 추출은 하위 클래스에 위임합니다.
     */
    public TrustAssessment assessContext() {
        try {
            // 컨텍스트 변경 감지를 위한 해시 계산 (하위 클래스 구현)
            String currentContextHash = calculateContextHash();
            
            // 캐시된 평가가 있고 컨텍스트가 변경되지 않았다면 재사용
            if (cachedAIAssessment != null && currentContextHash.equals(lastAssessmentContextHash)) {
                log.debug("AI 평가 캐시 재사용 - Hash: {}", currentContextHash);
                return cachedAIAssessment;
            }

            log.debug("AI 신뢰도 평가 시작 - 새로운 컨텍스트");
            
            // 현재 컨텍스트에서 정보 추출 (하위 클래스 구현)
            ContextExtractionResult extractedContext = extractCurrentContext();
            
            // 고급 AI-Native 위험 평가 수행 (공통 로직)
            double trustScore = performAdvancedAIRiskAssessment(
                extractedContext.remoteIp,
                extractedContext.userAgent,
                extractedContext.resourceIdentifier,
                extractedContext.actionType
            );
            
            // TrustAssessment 객체 생성
            this.cachedAIAssessment = createTrustAssessment(
                trustScore, 
                extractedContext.remoteIp, 
                extractedContext.resourceIdentifier, 
                extractedContext.actionType
            );
            
            this.lastAssessmentContextHash = currentContextHash;
            
            // AuthorizationContext와 연동 (CustomDynamicAuthorizationManager용)
            this.authorizationContext.attributes().put("ai_assessment", this.cachedAIAssessment);
            
            log.info("AI 신뢰도 평가 완료 - 점수: {}, 위험태그: {}", 
                     this.cachedAIAssessment.score(), this.cachedAIAssessment.riskTags());
            
            return this.cachedAIAssessment;
            
        } catch (Exception e) {
            log.error("AI 신뢰도 평가 실패: {}", e.getMessage(), e);
            
            // 실패 시 보수적 기본값 생성
            this.cachedAIAssessment = createFallbackTrustAssessment();
            this.authorizationContext.attributes().put("ai_assessment", this.cachedAIAssessment);
            
            return this.cachedAIAssessment;
        }
    }

    /**
     * [템플릿 메서드] 속성 조회
     * 
     * 공통 속성 조회 로직을 제공합니다.
     */
    public Object getAttribute(String key) {
        // 1. 캐시된 속성 확인
        if (authorizationContext.attributes().containsKey(key)) {
            return authorizationContext.attributes().get(key);
        }
        
        // 2. AttributePIP를 통한 동적 로딩
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

    /**
     * [추상 메서드] 현재 컨텍스트 추출
     * 하위 클래스에서 각각의 환경(웹/메서드)에 맞게 구현
     */
    protected abstract ContextExtractionResult extractCurrentContext();
    
    /**
     * [추상 메서드] 컨텍스트 해시 계산
     * 캐시 무효화를 위한 컨텍스트 변경 감지
     */
    protected abstract String calculateContextHash();

    // === 공통 내부 헬퍼 메서드들 (템플릿 메서드 패턴) ===

    protected double performAdvancedAIRiskAssessment(String remoteIp, String userAgent, 
                                                   String resourceIdentifier, String actionType) {
        long assessmentStart = System.currentTimeMillis();
        String assessmentId = "AI_EVAL_" + System.currentTimeMillis();
        
        log.debug("[{}] AI 위험 평가 시작 - IP: {}, Resource: {}", assessmentId, remoteIp, resourceIdentifier);
        
        try {
            // 1. 실무급 컨텍스트 구성
            RiskAssessmentContext context = buildComprehensiveRiskContext(
                remoteIp, userAgent, resourceIdentifier, actionType, assessmentId);
            
            // 2. AI-Native 위험 평가 실행
            RiskAssessmentResponse aiResponse = executeAIRiskAssessment(context, assessmentId);
            
            // 3. 업무 규칙과 통합하여 최종 신뢰도 계산
            double finalTrustScore = integrateAIWithBusinessRules(aiResponse, context, assessmentId);
            
            // 4. 종합 감사 로그 기록
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
            
            // 기본 접근 정보
            context.setResourceIdentifier(resourceIdentifier);
            context.setActionType(actionType);
            context.setRemoteIp(remoteIp);
            context.setUserAgent(userAgent);
            context.setLocation(determineGeographicLocation(remoteIp));
            
            // 사용자 역할 정보
            if (auth != null && auth.getAuthorities() != null) {
                List<String> roles = auth.getAuthorities().stream()
                    .map(authority -> authority.getAuthority())
                    .collect(Collectors.toList());
                context.setUserRoles(roles);
            }
            
            // 환경 속성 강화
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
                .block(); // 보안 평가는 동기 처리 필요

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
            
            // 업무 규칙 가중치 (간소화된 버전)
            double businessWeight = calculateBusinessWeight(context);
            double complianceWeight = calculateComplianceWeight(context);
            
            // 가중 평균 계산
            double finalScore = aiTrustScore * 0.7 + businessWeight * 0.2 + complianceWeight * 0.1;
            
            // 보안 임계치 적용
            if (aiResponse.riskScore() > 0.8) {
                finalScore = Math.min(finalScore, 0.4); // 고위험 시 제한
            }
            
            return Math.max(0.0, Math.min(1.0, finalScore));
            
        } catch (Exception e) {
            log.error("[{}] 점수 통합 실패: {}", assessmentId, e.getMessage());
            return 0.3; // 보수적 기본값
        }
    }

    /**
     * 감사 로그 기록 (트랜잭션 상태 확인)
     * 
     * read-only 트랜잭션에서는 감사 로그 기록을 건너뛰어 오류를 방지합니다.
     */
    private void recordAIAssessmentAudit(RiskAssessmentContext context, RiskAssessmentResponse aiResponse,
                                       double finalScore, String assessmentId) {
        try {
            // 현재 트랜잭션이 read-only인지 확인
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
            // 감사 로그 실패는 전체 프로세스를 중단시키지 않음
        }
    }

    // === 유틸리티 메서드들 ===

    private void enrichContextWithEnvironmentalFactors(RiskAssessmentContext context, String remoteIp,
                                                       String userAgent, String assessmentId) {
        try {
            LocalDateTime now = LocalDateTime.now();
            
            // 환경 속성 설정
            context.withEnvironmentAttribute("isBusinessHours", isBusinessHours(now));
            context.withEnvironmentAttribute("isWeekend", now.getDayOfWeek().getValue() >= 6);
            context.withEnvironmentAttribute("accessHour", now.getHour());
            context.withEnvironmentAttribute("isInternalNetwork", isInternalIP(remoteIp));
            context.withEnvironmentAttribute("deviceType", determineDeviceType(userAgent));
            
            // 행동 메트릭 기본값 설정 (NPE 방지 및 기본 분석 데이터 제공)
            if (context.getBehaviorMetrics() != null) {
                context.getBehaviorMetrics().put("mfaEnabled", "Unknown"); // 기본값
                context.getBehaviorMetrics().put("lastLoginHours", 24); // 가정값
                context.getBehaviorMetrics().put("sessionCount", 1); // 현재 세션
                context.getBehaviorMetrics().put("averageSessionDuration", 30); // 분 단위
                context.getBehaviorMetrics().put("deviceTrust", isInternalIP(remoteIp) ? "High" : "Medium");
                context.getBehaviorMetrics().put("locationConsistency", "Unknown");
                context.getBehaviorMetrics().put("accessPatternNormality", 0.8); // 기본 정상 패턴
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

    // === 간소화된 유틸리티 메서드들 ===

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

    /**
     * 컨텍스트 추출 결과를 담는 내부 클래스
     */
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
} 