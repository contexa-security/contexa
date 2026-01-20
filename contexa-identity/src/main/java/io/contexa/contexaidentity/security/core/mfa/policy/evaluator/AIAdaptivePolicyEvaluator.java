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


@Slf4j
public class AIAdaptivePolicyEvaluator implements MfaPolicyEvaluator {

    private final AICoreOperations aiCoreOperations;

    public AIAdaptivePolicyEvaluator(AICoreOperations aiCoreOperations) {
        this.aiCoreOperations = aiCoreOperations;
    }
    
    
    private static final long AI_ASSESSMENT_TIMEOUT_SECONDS = 3;
    private static final double BLOCK_THRESHOLD = 0.9;
    private static final double STRONG_MFA_THRESHOLD = 0.7;
    private static final double STANDARD_MFA_THRESHOLD = 0.3;
    private static final double NO_MFA_THRESHOLD = 0.1;
    
    
    @Override
    public MfaDecision evaluatePolicy(FactorContext context) {
        Assert.notNull(context, "FactorContext cannot be null");
        
        String username = context.getUsername();
        log.info("Starting AI adaptive policy evaluation for user: {}", username);
        
        
        AIAssessmentResult assessment = performAIAssessment(context);
        
        
        MfaDecision decision = convertToMfaDecision(assessment, context);
        
        log.info("AI policy evaluation completed for user {}: decision={}, riskScore={}", 
                username, decision.getType(), assessment.getRiskScore());
        
        return decision;
    }
    
    
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
            
            CompletableFuture<RiskAssessmentResponse> riskFuture = 
                CompletableFuture.supplyAsync(() -> 
                    assessRisk(context, ipAddress, userAgent));
            
            CompletableFuture<BehavioralAnalysisResponse> behaviorFuture = 
                CompletableFuture.supplyAsync(() -> 
                    analyzeBehavior(context, ipAddress));
            
            
            CompletableFuture<AIAssessmentResult> combinedFuture = 
                riskFuture.thenCombine(behaviorFuture, 
                    (risk, behavior) -> combineAssessments(risk, behavior, username));
            
            
            return combinedFuture.get(AI_ASSESSMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            
        } catch (TimeoutException e) {
            log.warn("AI assessment timeout for user: {}, applying conservative policy", username);
            return AIAssessmentResult.conservative();
        } catch (Exception e) {
            log.error("Error during AI assessment for user: {}", username, e);
            return AIAssessmentResult.conservative();
        }
    }
    
    
    private RiskAssessmentResponse assessRisk(
            FactorContext context, 
            String ipAddress, 
            String userAgent) {
        
        try {
            
            RiskAssessmentContext riskContext = RiskAssessmentContext.create(
                context.getUsername(),
                "authentication",
                "LOGIN"
            );
            
            riskContext.setSessionId(context.getMfaSessionId());
            riskContext.setRemoteIp(ipAddress);
            riskContext.setUserAgent(userAgent);
            
            
            Map<String, Object> envAttributes = riskContext.getEnvironmentAttributes();
            envAttributes.put("flowType", context.getFlowTypeName());
            envAttributes.put("authenticationTime", System.currentTimeMillis());
            envAttributes.put("loginAttempts", context.getRetryCount());
            
            
            RiskAssessmentRequest request = RiskAssessmentRequest.create(
                riskContext, 
                "riskAssessment"
            );
            
            
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
    
    
    private BehavioralAnalysisResponse analyzeBehavior(
            FactorContext context, 
            String ipAddress) {
        
        try {
            
            BehavioralAnalysisContext behaviorContext = new BehavioralAnalysisContext();
            behaviorContext.setUserId(context.getUsername());
            behaviorContext.setSessionId(context.getMfaSessionId());
            behaviorContext.setRemoteIp(ipAddress);
            behaviorContext.setCurrentActivity("LOGIN_ATTEMPT");
            
            
            String historicalSummary = String.format(
                "User %s login attempt from IP %s, failed attempts: %d",
                context.getUsername(), ipAddress, context.getFailedAttempts("LOGIN")
            );
            behaviorContext.setHistoricalBehaviorSummary(historicalSummary);
            
            
            BehavioralAnalysisRequest request = BehavioralAnalysisRequest.create(
                behaviorContext,
                "behavioralAnalysis"
            );
            
            
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
    
    
    private AIAssessmentResult combineAssessments(
            RiskAssessmentResponse riskResponse,
            BehavioralAnalysisResponse behaviorResponse,
            String username) {
        
        
        if (riskResponse == null && behaviorResponse == null) {
            log.warn("Both AI assessments failed for user: {}", username);
            return AIAssessmentResult.conservative();
        }
        
        
        double riskScore = 0.0;
        double weightSum = 0.0;
        
        if (riskResponse != null) {
            riskScore += (riskResponse.riskScore() / 100.0) * 0.6; 
            weightSum += 0.6;
        }
        
        if (behaviorResponse != null) {
            riskScore += (behaviorResponse.getBehavioralRiskScore() / 100.0) * 0.4; 
            weightSum += 0.4;
        }
        
        if (weightSum > 0) {
            riskScore = riskScore / weightSum;
        }
        
        
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
    
    
    private MfaDecision convertToMfaDecision(
            AIAssessmentResult assessment, 
            FactorContext context) {
        
        double riskScore = assessment.getRiskScore();
        
        
        if (riskScore >= BLOCK_THRESHOLD) {
            
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
    
    
    private HttpServletRequest getCurrentRequest() {
        ServletRequestAttributes attributes = 
            (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes != null ? attributes.getRequest() : null;
    }
    
    
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
    
    
    private RiskAssessmentResponse createDefaultRiskResponse() {
        
        return RiskAssessmentResponse.defaultSafe("default-request-id");
    }
    
    
    private BehavioralAnalysisResponse createDefaultBehaviorResponse() {
        BehavioralAnalysisResponse response = new BehavioralAnalysisResponse(
            "default-request-id", 
            BehavioralAnalysisResponse.ExecutionStatus.SUCCESS
        );
        response.setBehavioralRiskScore(50.0); 
        response.setRiskLevel(BehavioralAnalysisResponse.RiskLevel.MEDIUM);
        return response;
    }
    
    @Override
    public boolean supports(FactorContext context) {
        
        if (!isAvailable()) {
            return false;
        }
        
        if (context == null) {
            return false;
        }
        
        
        if (context.getAttribute("forceAI") != null) {
            return true;
        }
        
        
        if (context.getFailedAttempts("LOGIN") > 3) {
            return true;
        }
        
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
        return 10; 
    }
    
    
    private static class AIAssessmentResult {
        private final double riskScore;
        private final Map<String, Object> attributes;
        
        public AIAssessmentResult(double riskScore, Map<String, Object> attributes) {
            this.riskScore = riskScore;
            this.attributes = attributes != null ? attributes : Collections.emptyMap();
        }
        
        public static AIAssessmentResult conservative() {
            
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