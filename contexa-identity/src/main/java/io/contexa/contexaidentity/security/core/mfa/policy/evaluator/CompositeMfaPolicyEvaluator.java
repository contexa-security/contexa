package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;
import lombok.extern.slf4j.Slf4j;

import java.util.*;


@Slf4j
public class CompositeMfaPolicyEvaluator implements MfaPolicyEvaluator {
    
    private final List<MfaPolicyEvaluator> evaluators;
    private String lastUsedEvaluatorName = "None";
    
    
    public CompositeMfaPolicyEvaluator(List<MfaPolicyEvaluator> evaluators) {
        
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
    
    
    @Override
    public MfaDecision evaluatePolicy(FactorContext context) {
        log.debug("CompositeMfaPolicyEvaluator evaluating policy for user: {}", context.getUsername());
        
        
        Optional<MfaPolicyEvaluator> selectedEvaluator = findSuitableEvaluator(context);
        
        if (selectedEvaluator.isPresent()) {
            MfaPolicyEvaluator evaluator = selectedEvaluator.get();
            log.info("Selected evaluator: {} for user: {}", 
                evaluator.getName(), context.getUsername());
            
            
            lastUsedEvaluatorName = evaluator.getName();
            
            try {
                MfaDecision decision = evaluator.evaluatePolicy(context);
                
                
                
                Map<String, Object> updatedMetadata = new HashMap<>();
                if (decision.getMetadata() != null) {
                    updatedMetadata.putAll(decision.getMetadata());
                }
                updatedMetadata.put("evaluator", evaluator.getName());
                
                
                return decision.toBuilder()
                    .metadata(updatedMetadata)
                    .build();
            } catch (Exception e) {
                log.error("Error in evaluator {}: {}", evaluator.getName(), e.getMessage());
                
                return fallbackEvaluation(context, evaluator);
            }
        }
        
        
        log.error("No suitable evaluator found for user: {}", context.getUsername());
        return MfaDecision.noMfaRequired();
    }
    
    
    private Optional<MfaPolicyEvaluator> findSuitableEvaluator(FactorContext context) {
        
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
    
    
    private MfaDecision fallbackEvaluation(FactorContext context, MfaPolicyEvaluator failedEvaluator) {
        log.warn("Falling back from {} to next available evaluator", failedEvaluator.getName());
        
        
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
        
        
        log.error("All evaluators failed, returning conservative decision");
        return MfaDecision.standardMfa(2);
    }
    
    @Override
    public boolean supports(FactorContext context) {
        
        return true;
    }
    
    @Override
    public boolean isAvailable() {
        
        return evaluators.stream().anyMatch(MfaPolicyEvaluator::isAvailable);
    }
    
    @Override
    public int getPriority() {
        
        return Integer.MAX_VALUE;
    }
    
    @Override
    public String getName() {
        return "CompositeMfaPolicyEvaluator";
    }
    
    
    public List<MfaPolicyEvaluator> getEvaluators() {
        return evaluators;
    }
    
    
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
    
    
    public String getLastUsedEvaluatorName() {
        return lastUsedEvaluatorName;
    }
}