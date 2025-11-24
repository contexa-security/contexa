package io.contexa.contexaidentity.security.core.mfa.policy;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.CompositeMfaPolicyEvaluator;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
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
public class AIAdaptiveMfaPolicyProvider extends DefaultMfaPolicyProvider {
    
    private final CompositeMfaPolicyEvaluator compositePolicyEvaluator;
    private final AICoreOperations aiCoreOperations;

    /**
     * AI 적응형 MFA 정책 제공자 생성자
     *
     * @param userRepository 사용자 저장소
     * @param applicationContext Spring 애플리케이션 컨텍스트
     * @param properties 인증 컨텍스트 설정
     * @param compositePolicyEvaluator Composite 패턴 평가자
     * @param platformConfig 플랫폼 설정 (Phase 2 개선: 직접 주입)
     * @param aiCoreOperations AI 코어 오퍼레이션 (nullable)
     */
    public AIAdaptiveMfaPolicyProvider(
            UserRepository userRepository,
            ApplicationContext applicationContext,
            AuthContextProperties properties,
            CompositeMfaPolicyEvaluator compositePolicyEvaluator,
            PlatformConfig platformConfig,
            AICoreOperations aiCoreOperations) {

        super(userRepository, applicationContext, properties, compositePolicyEvaluator, platformConfig);
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
     * Phase 2: 초기 MFA 요구사항 평가 (읽기 전용)
     *
     * AI 기반 평가를 수행하고 결과를 반환합니다.
     * 부모 클래스의 evaluateInitialMfaRequirement()를 호출하여 표준 평가를 수행하고,
     * AI가 사용 가능한 경우 추가 메타데이터로 컨텍스트를 보강합니다.
     *
     * @param ctx MFA 팩터 컨텍스트
     * @return MFA 결정 정보 (읽기 전용)
     */
    @Override
    public MfaDecision evaluateInitialMfaRequirement(FactorContext ctx) {
        Assert.notNull(ctx, "FactorContext cannot be null");

        log.info("Starting MFA requirement evaluation for user: {} (AI: {})",
                ctx.getUsername(), isAIAvailable() ? "enabled" : "disabled");

        // 부모 클래스의 Phase 2 메서드를 호출하여 표준 평가 수행
        // 이 과정에서 getPolicyEvaluator()가 호출되어 적절한 평가자가 사용됨
        MfaDecision decision = super.evaluateInitialMfaRequirement(ctx);

        // AI 평가가 사용된 경우 추가 메타데이터 저장
        if (isAIAvailable()) {
            enrichContextWithAIMetadata(ctx);
        }

        return decision;
    }

    /**
     * AI 평가 메타데이터로 컨텍스트를 보강합니다.
     *
     * AI 평가가 수행된 경우, 평가 결과와 관련된 추가 정보를
     * 컨텍스트에 저장하여 후속 처리나 감사에 활용할 수 있도록 합니다.
     *
     * Phase 3.4: MfaDecision 객체는 Kryo 직렬화 불가이므로,
     * InitializeMfaAction에서 저장한 개별 속성들을 직접 사용합니다.
     *
     * @param ctx MFA 팩터 컨텍스트
     */
    private void enrichContextWithAIMetadata(FactorContext ctx) {
        // Phase 3.4: MfaDecision 객체는 저장되지 않으므로, 이미 저장된 속성들을 직접 사용
        // InitializeMfaAction에서 decision.getMetadata().forEach(ctx::setAttribute)로 복사된 속성 활용

        Object riskScore = ctx.getAttribute("riskScore");
        if (riskScore != null) {
            ctx.setAttribute("aiRiskScore", riskScore);
            log.debug("AI risk score for user {}: {}", ctx.getUsername(), riskScore);
        }

        Object aiAttributes = ctx.getAttribute("aiAttributes");
        if (aiAttributes != null) {
            ctx.setAttribute("aiAssessmentDetails", aiAttributes);
        }

        // 차단 결정인 경우 추가 로깅 (InitializeMfaAction Line 92-96에서 설정됨)
        Boolean blocked = (Boolean) ctx.getAttribute("blocked");
        if (Boolean.TRUE.equals(blocked)) {
            String blockReason = (String) ctx.getAttribute("blockReason");
            log.warn("AI blocked authentication for user: {} - Reason: {}",
                    ctx.getUsername(), blockReason != null ? blockReason : "UNKNOWN");
        }

        // DecisionType 로깅 (InitializeMfaAction Line 80에서 설정됨)
        String decisionType = (String) ctx.getAttribute("mfaDecisionType");
        if (decisionType != null) {
            log.info("AI-enhanced MFA evaluation completed for user {}: Decision type={}",
                    ctx.getUsername(), decisionType);
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