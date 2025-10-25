package io.contexa.contexaidentity.security.core.mfa.policy;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.CompositeMfaPolicyEvaluator;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

/**
 * AI 적응형 MFA 정책 제공자 (Zero Trust 통합)
 * 
 * DefaultMfaPolicyProvider를 확장하여 Zero Trust 기반 실시간 위험 평가를 통한
 * 적응형 인증 정책을 제공합니다.
 * 
 * 이 클래스는 Redis에 저장된 threat_score를 실시간으로 조회하여
 * 동기적 AI 호출 없이 밀리초 단위로 MFA 정책을 결정합니다.
 * 
 * 주요 기능:
 * 1. ZeroTrustPolicyEvaluator를 통한 실시간 위험 평가
 * 2. Redis 기반 threat_score 조회 (5ms 이내)
 * 3. Caffeine 로컬 캐시 적용 (1초 TTL)
 * 4. AI 사용 불가 시 기본 정책으로 폴백
 * 
 * @author contexa
 * @since 2.0
 */
@Slf4j
@Component
@Primary
public class AIAdaptiveMfaPolicyProvider extends DefaultMfaPolicyProvider {
    
    private final CompositeMfaPolicyEvaluator compositePolicyEvaluator;
    private final AICoreOperations aiCoreOperations;

    /**
     * AI 적응형 MFA 정책 제공자 생성자
     * 
     * @param userRepository 사용자 저장소
     * @param applicationContext Spring 애플리케이션 컨텍스트
     * @param stateMachineIntegrator MFA 상태 머신 통합자
     * @param properties 인증 컨텍스트 설정
     * @param compositePolicyEvaluator Composite 패턴 평가자
     * @param aiCoreOperations AI 코어 오퍼레이션 (nullable)
     */
    public AIAdaptiveMfaPolicyProvider(
            UserRepository userRepository,
            ApplicationContext applicationContext,
            MfaStateMachineIntegrator stateMachineIntegrator,
            AuthContextProperties properties,
            CompositeMfaPolicyEvaluator compositePolicyEvaluator,
            AICoreOperations aiCoreOperations) {
        
        super(userRepository, applicationContext, stateMachineIntegrator, properties, compositePolicyEvaluator);
        this.compositePolicyEvaluator = compositePolicyEvaluator;
        this.aiCoreOperations = aiCoreOperations;

        if (aiCoreOperations == null) {
            log.warn("AI Core Operations not available. AI adaptive authentication will be disabled.");
        }
        
        // 시작 시 평가자 상태 로깅
        compositePolicyEvaluator.logEvaluatorStatus();
    }
    
    /**
     * MFA 정책을 평가합니다.
     * 
     * Composite 패턴을 사용하여 컨텍스트에 따라 적절한 평가자를 자동 선택합니다.
     * 
     * @param ctx MFA 팩터 컨텍스트
     * @return MFA 결정
     */
    @Override
    protected MfaDecision evaluatePolicy(FactorContext ctx) {
        MfaDecision decision = compositePolicyEvaluator.evaluatePolicy(ctx);
        
        log.info("MFA policy evaluated for user {}: type={}, required={}, factorCount={}, evaluator={}",
                ctx.getUsername(), decision.getType(), decision.isRequired(), 
                decision.getFactorCount(), compositePolicyEvaluator.getLastUsedEvaluatorName());
        
        return decision;
    }
    
    /**
     * MFA 요구사항 평가 및 초기 단계 결정
     * 
     * 이 메서드는 부모 클래스의 기본 구현을 재사용하면서
     * AI 기반 평가 결과를 컨텍스트에 추가로 저장합니다.
     * 
     * @param ctx MFA 팩터 컨텍스트
     */
    @Override
    public void evaluateMfaRequirementAndDetermineInitialStep(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null");
        
        log.info("Starting MFA requirement evaluation for user: {} (AI: {})", 
                ctx.getUsername(), isAIAvailable() ? "enabled" : "disabled");
        
        // 부모 클래스의 메서드를 호출하여 표준 플로우 실행
        // 이 과정에서 getPolicyEvaluator()가 호출되어 적절한 평가자가 사용됨
        super.evaluateMfaRequirementAndDetermineInitialStep(ctx);
        
        // AI 평가가 사용된 경우 추가 메타데이터 저장
        if (isAIAvailable()) {
            enrichContextWithAIMetadata(ctx);
        }
    }
    
    /**
     * AI 평가 메타데이터로 컨텍스트를 보강합니다.
     * 
     * AI 평가가 수행된 경우, 평가 결과와 관련된 추가 정보를
     * 컨텍스트에 저장하여 후속 처리나 감사에 활용할 수 있도록 합니다.
     * 
     * @param ctx MFA 팩터 컨텍스트
     */
    private void enrichContextWithAIMetadata(FactorContext ctx) {
        // mfaDecision 속성이 이미 부모 클래스에서 설정됨
        Object decisionObj = ctx.getAttribute("mfaDecision");
        
        if (decisionObj instanceof MfaDecision) {
            MfaDecision decision = (MfaDecision) decisionObj;
            
            // AI 평가 플래그 설정
            ctx.setAttribute("aiEvaluated", true);
            ctx.setAttribute("aiEvaluatorUsed", "AIAdaptivePolicyEvaluator");
            
            // 메타데이터에서 AI 관련 정보 추출
            if (decision.getMetadata() != null) {
                Object riskScore = decision.getMetadata().get("riskScore");
                if (riskScore != null) {
                    ctx.setAttribute("aiRiskScore", riskScore);
                    log.debug("AI risk score for user {}: {}", ctx.getUsername(), riskScore);
                }
                
                Object aiAttributes = decision.getMetadata().get("aiAttributes");
                if (aiAttributes != null) {
                    ctx.setAttribute("aiAssessmentDetails", aiAttributes);
                }
            }
            
            // 차단 결정인 경우 추가 로깅
            if (decision.isBlocked()) {
                log.warn("AI blocked authentication for user: {} - Reason: {}", 
                        ctx.getUsername(), decision.getReason());
            }
            
            log.info("AI-enhanced MFA evaluation completed for user {}: Decision type={}", 
                    ctx.getUsername(), decision.getType());
        }
    }
    
    /**
     * AI Core Operations가 사용 가능한지 확인합니다.
     * 
     * @return AI 사용 가능 여부
     */
    private boolean isAIAvailable() {
        return aiCoreOperations != null;
    }
}