package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.domain.context.BehavioralAnalysisContext;
import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.domain.request.BehavioralAnalysisRequest;
import io.contexa.contexacommon.domain.request.RiskAssessmentRequest;
import io.contexa.contexacommon.domain.response.BehavioralAnalysisResponse;
import io.contexa.contexacommon.domain.response.RiskAssessmentResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * AI 적응형 MFA 정책 평가자
 *
 * AI Labs (RiskAssessmentLab, BehavioralAnalysisLab)를 활용하여
 * 실시간 위험 평가와 행동 분석을 기반으로 적응형 MFA 정책을 결정합니다.
 *
 * 주요 기능:
 * - 실시간 위험도 평가
 * - 사용자 행동 패턴 분석
 * - 동적 MFA 레벨 결정
 * - 고위험 상황 차단
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j
public class AIAdaptivePolicyEvaluator implements MfaPolicyEvaluator {

    private final AICoreOperations aiCoreOperations;

    public AIAdaptivePolicyEvaluator(AICoreOperations aiCoreOperations) {
        this.aiCoreOperations = aiCoreOperations;
    }
    
    // AI 평가 설정
    private static final long AI_ASSESSMENT_TIMEOUT_SECONDS = 3;
    private static final double BLOCK_THRESHOLD = 0.9;
    private static final double STRONG_MFA_THRESHOLD = 0.7;
    private static final double STANDARD_MFA_THRESHOLD = 0.3;
    private static final double NO_MFA_THRESHOLD = 0.1;
    
    /**
     * AI 기반으로 MFA 정책을 평가합니다.
     */
    @Override
    public MfaDecision evaluatePolicy(FactorContext context) {
        Assert.notNull(context, "FactorContext cannot be null");
        
        String username = context.getUsername();
        log.info("Starting AI adaptive policy evaluation for user: {}", username);
        
        // AI 평가 수행
        AIAssessmentResult assessment = performAIAssessment(context);
        
        // AI 평가 결과를 MfaDecision 으로 변환
        MfaDecision decision = convertToMfaDecision(assessment, context);
        
        log.info("AI policy evaluation completed for user {}: decision={}, riskScore={}", 
                username, decision.getType(), assessment.getRiskScore());
        
        return decision;
    }
    
    /**
     * AI 평가를 수행합니다.
     */
    private AIAssessmentResult performAIAssessment(FactorContext context) {
        HttpServletRequest request = getCurrentRequest();
        
        if (request == null) {
            log.warn("HTTP request not available for AI assessment, using conservative defaults");
            return AIAssessmentResult.conservative();
        }
        
        String username = context.getUsername();
        String ipAddress = extractIpAddress(request);
        String userAgent = request.getHeader("User-Agent");
        
        try {
            // 병렬로 위험 평가와 행동 분석 실행
            CompletableFuture<RiskAssessmentResponse> riskFuture = 
                CompletableFuture.supplyAsync(() -> 
                    assessRisk(context, ipAddress, userAgent));
            
            CompletableFuture<BehavioralAnalysisResponse> behaviorFuture = 
                CompletableFuture.supplyAsync(() -> 
                    analyzeBehavior(context, ipAddress));
            
            // 결과 병합
            CompletableFuture<AIAssessmentResult> combinedFuture = 
                riskFuture.thenCombine(behaviorFuture, 
                    (risk, behavior) -> combineAssessments(risk, behavior, username));
            
            // 타임아웃 적용
            return combinedFuture.get(AI_ASSESSMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            
        } catch (TimeoutException e) {
            log.warn("AI assessment timeout for user: {}, applying conservative policy", username);
            return AIAssessmentResult.conservative();
        } catch (Exception e) {
            log.error("Error during AI assessment for user: {}", username, e);
            return AIAssessmentResult.conservative();
        }
    }
    
    /**
     * 위험 평가를 수행합니다.
     */
    private RiskAssessmentResponse assessRisk(
            FactorContext context, 
            String ipAddress, 
            String userAgent) {
        
        try {
            // 위험 평가 컨텍스트 생성
            RiskAssessmentContext riskContext = RiskAssessmentContext.create(
                context.getUsername(),
                "authentication",
                "LOGIN"
            );
            
            riskContext.setSessionId(context.getMfaSessionId());
            riskContext.setRemoteIp(ipAddress);
            riskContext.setUserAgent(userAgent);
            
            // 환경 속성 추가
            Map<String, Object> envAttributes = riskContext.getEnvironmentAttributes();
            envAttributes.put("flowType", context.getFlowTypeName());
            envAttributes.put("authenticationTime", System.currentTimeMillis());
            envAttributes.put("loginAttempts", context.getRetryCount());
            
            // AI 평가 요청
            RiskAssessmentRequest request = RiskAssessmentRequest.create(
                riskContext, 
                "riskAssessment"
            );
            
            // 동기 실행 (CompletableFuture 내부에서 실행됨)
            Mono<RiskAssessmentResponse> responseMono = 
                aiCoreOperations.process(request, RiskAssessmentResponse.class);
            
            RiskAssessmentResponse response = responseMono
                .timeout(Duration.ofSeconds(AI_ASSESSMENT_TIMEOUT_SECONDS))
                .block();
            
            log.debug("Risk assessment completed for user {}: score={}", 
                    context.getUsername(), 
                    response != null ? response.riskScore() : "N/A");
            
            return response;
            
        } catch (Exception e) {
            log.error("Risk assessment failed for user: {}", context.getUsername(), e);
            return createDefaultRiskResponse();
        }
    }
    
    /**
     * 행동 분석을 수행합니다.
     */
    private BehavioralAnalysisResponse analyzeBehavior(
            FactorContext context, 
            String ipAddress) {
        
        try {
            // 행동 분석 컨텍스트 생성
            BehavioralAnalysisContext behaviorContext = new BehavioralAnalysisContext();
            behaviorContext.setUserId(context.getUsername());
            behaviorContext.setSessionId(context.getMfaSessionId());
            behaviorContext.setRemoteIp(ipAddress);
            behaviorContext.setCurrentActivity("LOGIN_ATTEMPT");
            
            // 과거 행동 요약 설정
            String historicalSummary = String.format(
                "User %s login attempt from IP %s, failed attempts: %d",
                context.getUsername(), ipAddress, context.getFailedAttempts("LOGIN")
            );
            behaviorContext.setHistoricalBehaviorSummary(historicalSummary);
            
            // AI 분석 요청
            BehavioralAnalysisRequest request = BehavioralAnalysisRequest.create(
                behaviorContext,
                "behavioralAnalysis"
            );
            
            // 동기 실행
            Mono<BehavioralAnalysisResponse> responseMono = 
                aiCoreOperations.process(request, BehavioralAnalysisResponse.class);
            
            BehavioralAnalysisResponse response = responseMono
                .timeout(Duration.ofSeconds(AI_ASSESSMENT_TIMEOUT_SECONDS))
                .block();
            
            log.debug("Behavioral analysis completed for user {}: behavioralRiskScore={}", 
                    context.getUsername(), 
                    response != null ? response.getBehavioralRiskScore() : "N/A");
            
            return response;
            
        } catch (Exception e) {
            log.error("Behavioral analysis failed for user: {}", context.getUsername(), e);
            return createDefaultBehaviorResponse();
        }
    }
    
    /**
     * 위험 평가와 행동 분석 결과를 병합합니다.
     */
    private AIAssessmentResult combineAssessments(
            RiskAssessmentResponse riskResponse,
            BehavioralAnalysisResponse behaviorResponse,
            String username) {
        
        // Null 체크
        if (riskResponse == null && behaviorResponse == null) {
            log.warn("Both AI assessments failed for user: {}", username);
            return AIAssessmentResult.conservative();
        }
        
        // 위험 점수 계산 (가중 평균)
        double riskScore = 0.0;
        double weightSum = 0.0;
        
        if (riskResponse != null) {
            riskScore += (riskResponse.riskScore() / 100.0) * 0.6; // 60% 가중치 (100점 만점을 1.0으로 정규화)
            weightSum += 0.6;
        }
        
        if (behaviorResponse != null) {
            riskScore += (behaviorResponse.getBehavioralRiskScore() / 100.0) * 0.4; // 40% 가중치
            weightSum += 0.4;
        }
        
        if (weightSum > 0) {
            riskScore = riskScore / weightSum;
        }
        
        // 추가 속성 수집
        Map<String, Object> attributes = new HashMap<>();
        
        if (riskResponse != null) {
            attributes.put("riskScore", riskResponse.riskScore());
            attributes.put("trustScore", riskResponse.trustScore());
            attributes.put("recommendation", riskResponse.recommendation());
        }
        
        if (behaviorResponse != null) {
            attributes.put("behavioralRiskScore", behaviorResponse.getBehavioralRiskScore());
            attributes.put("riskLevel", behaviorResponse.getRiskLevel());
            attributes.put("anomalies", behaviorResponse.getAnomalies());
        }
        
        return new AIAssessmentResult(riskScore, attributes);
    }
    
    /**
     * AI 평가 결과를 MfaDecision으로 변환합니다.
     */
    private MfaDecision convertToMfaDecision(
            AIAssessmentResult assessment, 
            FactorContext context) {
        
        double riskScore = assessment.getRiskScore();
        
        // 위험도에 따른 결정
        if (riskScore >= BLOCK_THRESHOLD) {
            // 차단
            return MfaDecision.builder()
                .required(false)
                .factorCount(0)
                .type(MfaDecision.DecisionType.BLOCKED)
                .reason("High risk detected: " + String.format("%.2f", riskScore))
                .metadata(Map.of(
                    "blocked", true,
                    "blockReason", "AI risk assessment: High risk",
                    "riskScore", riskScore,
                    "aiAttributes", assessment.getAttributes()
                ))
                .build();
                
        } else if (riskScore >= STRONG_MFA_THRESHOLD) {
            // 강화된 MFA (3개 팩터)
            return MfaDecision.builder()
                .required(true)
                .factorCount(3)
                .type(MfaDecision.DecisionType.STRONG_MFA)
                .requiredFactors(Arrays.asList(AuthType.PASSKEY, AuthType.OTT, AuthType.MFA))
                .reason("Elevated risk detected: " + String.format("%.2f", riskScore))
                .metadata(Map.of(
                    "riskScore", riskScore,
                    "aiAttributes", assessment.getAttributes()
                ))
                .build();
                
        } else if (riskScore >= STANDARD_MFA_THRESHOLD) {
            // 표준 MFA (2개 팩터)
            return MfaDecision.builder()
                .required(true)
                .factorCount(2)
                .type(MfaDecision.DecisionType.AI_ADAPTIVE_MFA)
                .requiredFactors(Arrays.asList(AuthType.PASSKEY, AuthType.OTT))
                .reason("Moderate risk detected: " + String.format("%.2f", riskScore))
                .metadata(Map.of(
                    "riskScore", riskScore,
                    "aiAttributes", assessment.getAttributes()
                ))
                .build();
                
        } else if (riskScore >= NO_MFA_THRESHOLD) {
            // 단일 팩터 MFA
            return MfaDecision.builder()
                .required(true)
                .factorCount(1)
                .type(MfaDecision.DecisionType.AI_ADAPTIVE_MFA)
                .requiredFactors(List.of(AuthType.PASSKEY))
                .reason("Low risk detected: " + String.format("%.2f", riskScore))
                .metadata(Map.of(
                    "riskScore", riskScore,
                    "aiAttributes", assessment.getAttributes()
                ))
                .build();
                
        } else {
            // MFA 불필요
            return MfaDecision.builder()
                .required(false)
                .factorCount(0)
                .type(MfaDecision.DecisionType.NO_MFA_REQUIRED)
                .reason("Very low risk: " + String.format("%.2f", riskScore))
                .metadata(Map.of(
                    "riskScore", riskScore,
                    "aiAttributes", assessment.getAttributes()
                ))
                .build();
        }
    }
    
    /**
     * 현재 HTTP 요청을 가져옵니다.
     */
    private HttpServletRequest getCurrentRequest() {
        ServletRequestAttributes attributes = 
            (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes != null ? attributes.getRequest() : null;
    }
    
    /**
     * IP 주소를 추출합니다.
     */
    private String extractIpAddress(HttpServletRequest request) {
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
    
    /**
     * 기본 위험 평가 응답을 생성합니다.
     */
    private RiskAssessmentResponse createDefaultRiskResponse() {
        // 기본 안전 위험 평가 응답 생성
        return RiskAssessmentResponse.defaultSafe("default-request-id");
    }
    
    /**
     * 기본 행동 분석 응답을 생성합니다.
     */
    private BehavioralAnalysisResponse createDefaultBehaviorResponse() {
        BehavioralAnalysisResponse response = new BehavioralAnalysisResponse(
            "default-request-id", 
            BehavioralAnalysisResponse.ExecutionStatus.SUCCESS
        );
        response.setBehavioralRiskScore(50.0); // 중간 위험 점수
        response.setRiskLevel(BehavioralAnalysisResponse.RiskLevel.MEDIUM);
        return response;
    }
    
    @Override
    public boolean supports(FactorContext context) {
        // AI 평가자는 AI가 사용 가능하고, forceAI 속성이 있거나 고위험 상황에서 지원
        /*if (!isAvailable()) {
            return false;
        }
        
        if (context == null) {
            return false;
        }
        
        // forceAI 속성이 있으면 지원
        if (context.getAttribute("forceAI") != null) {
            return true;
        }
        
        // 고위험 상황 (실패 횟수가 많은 경우) 지원
        if (context.getFailedAttempts("LOGIN") > 3) {
            return true;
        }*/
        
        return false;
    }
    
    @Override
    public boolean isAvailable() {
        return aiCoreOperations != null;
    }
    
    @Override
    public String getName() {
        return "AIAdaptivePolicyEvaluator";
    }
    
    @Override
    public int getPriority() {
        return 10; // 높은 우선순위
    }
    
    /**
     * AI 평가 결과를 담는 내부 클래스
     */
    private static class AIAssessmentResult {
        private final double riskScore;
        private final Map<String, Object> attributes;
        
        public AIAssessmentResult(double riskScore, Map<String, Object> attributes) {
            this.riskScore = riskScore;
            this.attributes = attributes != null ? attributes : Collections.emptyMap();
        }
        
        public static AIAssessmentResult conservative() {
            // 보수적 정책: 중간 위험도로 평가
            return new AIAssessmentResult(0.5, Map.of(
                "fallback", true,
                "reason", "AI assessment unavailable"
            ));
        }
        
        public double getRiskScore() {
            return riskScore;
        }
        
        public Map<String, Object> getAttributes() {
            return attributes;
        }
    }
}