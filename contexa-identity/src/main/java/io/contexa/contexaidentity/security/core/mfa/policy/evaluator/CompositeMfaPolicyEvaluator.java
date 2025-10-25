package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Composite 패턴을 사용한 MFA 정책 평가자
 *
 * 여러 MfaPolicyEvaluator를 관리하고,
 * 각 평가자의 supports() 메서드를 통해 적절한 평가자를 선택합니다.
 *
 * 우선순위:
 * 1. ZeroTrustPolicyEvaluator (priority: 100) - Redis 기반 실시간 평가
 * 2. AIAdaptivePolicyEvaluator (priority: 10) - AI 기반 평가
 * 3. DefaultMfaPolicyEvaluator (priority: -100) - 기본 폴백
 *
 * @Primary로 지정되어 DefaultMfaPolicyProvider가 이 Bean을 주입받습니다.
 *
 * @author contexa
 * @since 2.0
 */
@Slf4j
@Component
@Primary
public class CompositeMfaPolicyEvaluator implements MfaPolicyEvaluator {
    
    private final List<MfaPolicyEvaluator> evaluators;
    private String lastUsedEvaluatorName = "None";
    
    /**
     * 생성자 - Spring이 모든 MfaPolicyEvaluator 구현체를 주입
     * 
     * @param evaluators 사용 가능한 모든 MFA 정책 평가자들
     */
    public CompositeMfaPolicyEvaluator(List<MfaPolicyEvaluator> evaluators) {
        // 자기 자신은 제외하고 우선순위 순으로 정렬
        this.evaluators = evaluators.stream()
            .filter(e -> !(e instanceof CompositeMfaPolicyEvaluator))
            .sorted(Comparator.comparingInt(MfaPolicyEvaluator::getPriority).reversed())
            .toList();
        
        log.info("CompositeMfaPolicyEvaluator initialized with {} evaluators", this.evaluators.size());
        this.evaluators.forEach(e -> 
            log.info("  - {} (priority: {}, available: {})", 
                e.getName(), e.getPriority(), e.isAvailable())
        );
    }
    
    /**
     * 주어진 컨텍스트를 지원하는 적절한 평가자를 찾아 정책을 평가합니다.
     * 
     * @param context 평가할 팩터 컨텍스트
     * @return MFA 결정
     */
    @Override
    public MfaDecision evaluatePolicy(FactorContext context) {
        log.debug("CompositeMfaPolicyEvaluator evaluating policy for user: {}", context.getUsername());
        
        // supports() 메서드를 통해 적절한 평가자 찾기
        Optional<MfaPolicyEvaluator> selectedEvaluator = findSuitableEvaluator(context);
        
        if (selectedEvaluator.isPresent()) {
            MfaPolicyEvaluator evaluator = selectedEvaluator.get();
            log.info("Selected evaluator: {} for user: {}", 
                evaluator.getName(), context.getUsername());
            
            // 마지막 사용된 평가자 이름 저장
            lastUsedEvaluatorName = evaluator.getName();
            
            try {
                MfaDecision decision = evaluator.evaluatePolicy(context);
                
                // 선택된 평가자 정보를 메타데이터에 추가
                // metadata가 immutable일 수 있으므로 새로운 맵 생성
                Map<String, Object> updatedMetadata = new HashMap<>();
                if (decision.getMetadata() != null) {
                    updatedMetadata.putAll(decision.getMetadata());
                }
                updatedMetadata.put("evaluator", evaluator.getName());
                
                // 새로운 메타데이터로 MfaDecision 재구성
                return decision.toBuilder()
                    .metadata(updatedMetadata)
                    .build();
            } catch (Exception e) {
                log.error("Error in evaluator {}: {}", evaluator.getName(), e.getMessage());
                // 오류 발생 시 다음 평가자 시도
                return fallbackEvaluation(context, evaluator);
            }
        }
        
        // 적절한 평가자를 찾지 못한 경우 (발생하면 안 됨 - DefaultMfaPolicyEvaluator가 항상 있음)
        log.error("No suitable evaluator found for user: {}", context.getUsername());
        return MfaDecision.noMfaRequired();
    }
    
    /**
     * 주어진 컨텍스트를 지원하는 평가자를 찾습니다.
     * 
     * @param context 팩터 컨텍스트
     * @return 적절한 평가자 (Optional)
     */
    private Optional<MfaPolicyEvaluator> findSuitableEvaluator(FactorContext context) {
        // 우선순위가 높은 순서대로 확인
        for (MfaPolicyEvaluator evaluator : evaluators) {
            if (evaluator.supports(context)) {
                log.debug("Evaluator {} supports the context", evaluator.getName());
                return Optional.of(evaluator);
            } else {
                log.trace("Evaluator {} does not support the context", evaluator.getName());
            }
        }
        
        return Optional.empty();
    }
    
    /**
     * 평가자 실패 시 폴백 처리
     * 
     * @param context 팩터 컨텍스트
     * @param failedEvaluator 실패한 평가자
     * @return 폴백 MFA 결정
     */
    private MfaDecision fallbackEvaluation(FactorContext context, MfaPolicyEvaluator failedEvaluator) {
        log.warn("Falling back from {} to next available evaluator", failedEvaluator.getName());
        
        // 실패한 평가자 다음부터 다시 시도
        boolean skipNext = true;
        for (MfaPolicyEvaluator evaluator : evaluators) {
            if (evaluator == failedEvaluator) {
                skipNext = false;
                continue;
            }
            
            if (skipNext) {
                continue;
            }
            
            if (evaluator.supports(context)) {
                try {
                    log.info("Fallback to evaluator: {}", evaluator.getName());
                    return evaluator.evaluatePolicy(context);
                } catch (Exception e) {
                    log.error("Fallback evaluator {} also failed: {}", 
                        evaluator.getName(), e.getMessage());
                }
            }
        }
        
        // 모든 평가자가 실패한 경우 안전한 기본값 반환
        log.error("All evaluators failed, returning conservative decision");
        return MfaDecision.standardMfa(2);
    }
    
    @Override
    public boolean supports(FactorContext context) {
        // Composite는 항상 지원 (내부에서 적절한 평가자를 찾음)
        return true;
    }
    
    @Override
    public boolean isAvailable() {
        // 하나라도 사용 가능한 평가자가 있으면 true
        return evaluators.stream().anyMatch(MfaPolicyEvaluator::isAvailable);
    }
    
    @Override
    public int getPriority() {
        // Composite는 최고 우선순위
        return Integer.MAX_VALUE;
    }
    
    @Override
    public String getName() {
        return "CompositeMfaPolicyEvaluator";
    }
    
    /**
     * 현재 등록된 평가자 목록을 반환합니다.
     * 
     * @return 평가자 목록
     */
    public List<MfaPolicyEvaluator> getEvaluators() {
        return evaluators;
    }
    
    /**
     * 평가자 상태를 로깅합니다.
     */
    public void logEvaluatorStatus() {
        log.info("=== MFA Policy Evaluator Status ===");
        for (MfaPolicyEvaluator evaluator : evaluators) {
            log.info("{}: priority={}, available={}", 
                evaluator.getName(), 
                evaluator.getPriority(), 
                evaluator.isAvailable()
            );
        }
        log.info("===================================");
    }
    
    /**
     * 마지막으로 사용된 평가자의 이름을 반환합니다.
     * 
     * @return 마지막 사용된 평가자 이름
     */
    public String getLastUsedEvaluatorName() {
        return lastUsedEvaluatorName;
    }
}