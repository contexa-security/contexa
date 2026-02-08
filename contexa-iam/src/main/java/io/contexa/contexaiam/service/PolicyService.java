package io.contexa.contexaiam.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.event.PolicyApprovedEvent;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.prp.DatabasePolicyRetrievalPoint;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class PolicyService {

    private final PolicyRepository policyRepository;

    @Autowired(required = false)
    private DatabasePolicyRetrievalPoint policyRetrievalPoint;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Transactional(readOnly = true)
    public Policy findById(Long id) {
        return policyRepository.findById(id).orElse(null);
    }

    @Transactional
    public Policy save(Policy policy) {
        return policyRepository.save(policy);
    }


    @EventListener
    @Async
    @Transactional
    public void onPolicyApproved(PolicyApprovedEvent event) {
        try {

            Map<String, Object> policyRules = parsePolicyRules(event.getPolicyRules());
            if (!validatePolicyRules(policyRules)) {
                log.error("Invalid policy rules in PolicyApprovedEvent: {}", event.getPolicyId());
                return;
            }

            Policy policy = Policy.builder()
                .name(event.getPolicyName())
                .description(event.getPolicyDescription())
                .effect(determineEffectFromRules(policyRules)) 
                .priority(determinePriorityFromRules(policyRules)) 
                .source(Policy.PolicySource.AI_EVOLVED)
                .approvalStatus(Policy.ApprovalStatus.APPROVED)
                .confidenceScore(event.getConfidenceScore())
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .approvedBy(event.getApprovedBy())
                .approvedAt(LocalDateTime.now())
                .isActive(true)
                .aiModel("AutonomousLearningCoordinator")
                .build();

            String detailedDescription = event.getPolicyDescription() +
                "\n[Evolution Metadata] Original Policy ID: " + event.getPolicyId() +
                ", Confidence: " + event.getConfidenceScore() +
                ", Target System: " + event.getTargetSystem();
            policy.setFriendlyDescription(detailedDescription);

            createPolicyRulesAndTargets(policy, policyRules);

            Policy savedPolicy = policyRepository.save(policy);

            loadPolicyToXacmlEngine(savedPolicy);

            validatePolicyApplication(savedPolicy);

        } catch (Exception e) {
            log.error("Failed to process PolicyApprovedEvent: {}", event, e);
            
        }
    }

    private Map<String, Object> parsePolicyRules(String policyRulesJson) {
        try {
            if (policyRulesJson == null || policyRulesJson.trim().isEmpty()) {
                return new HashMap<>();
            }
            return objectMapper.readValue(policyRulesJson, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            log.error("Failed to parse policy rules JSON: {}", policyRulesJson, e);
            return new HashMap<>();
        }
    }

    private boolean validatePolicyRules(Map<String, Object> policyRules) {
        if (policyRules.isEmpty()) {
            log.warn("Empty policy rules detected");
            return false;
        }

        if (!policyRules.containsKey("effect") || !policyRules.containsKey("targets")) {
            log.error("Missing required fields in policy rules: effect or targets");
            return false;
        }

        String effect = (String) policyRules.get("effect");
        if (!"ALLOW".equals(effect) && !"DENY".equals(effect)) {
            log.error("Invalid effect value: {}", effect);
            return false;
        }

        return true;
    }

    private Policy.Effect determineEffectFromRules(Map<String, Object> policyRules) {
        String effect = (String) policyRules.getOrDefault("effect", "ALLOW");
        return "DENY".equals(effect) ? Policy.Effect.DENY : Policy.Effect.ALLOW;
    }

    private int determinePriorityFromRules(Map<String, Object> policyRules) {
        Integer priority = (Integer) policyRules.get("priority");
        return priority != null ? priority : 100; 
    }

    private void createPolicyRulesAndTargets(Policy policy, Map<String, Object> policyRules) {
        try {
            
            Map<String, Object> targets = (Map<String, Object>) policyRules.get("targets");
            if (targets != null) {
                for (Map.Entry<String, Object> targetEntry : targets.entrySet()) {
                    PolicyTarget target = PolicyTarget.builder()
                        .targetType(targetEntry.getKey())
                        .targetIdentifier(targetEntry.getValue().toString())
                        .httpMethod("ALL") 
                        .build();
                    policy.addTarget(target);
                }
            }

            Map<String, Object> rules = (Map<String, Object>) policyRules.getOrDefault("rules", new HashMap<>());
            for (Map.Entry<String, Object> ruleEntry : rules.entrySet()) {
                PolicyRule rule = PolicyRule.builder()
                    .description("AI evolved rule: " + ruleEntry.getKey() + " - " + ruleEntry.getValue().toString())
                    .build();
                policy.addRule(rule);
            }

            if (policy.getRules().isEmpty()) {
                PolicyRule defaultRule = PolicyRule.builder()
                    .description("AI evolved default policy - allows access based on evolution analysis")
                    .build();
                policy.addRule(defaultRule);
            }

        } catch (Exception e) {
            log.error("Failed to create policy rules and targets", e);
        }
    }

    private void loadPolicyToXacmlEngine(Policy policy) {
        try {
            if (policyRetrievalPoint != null) {
                
                if ("URL".equals(getTargetType(policy))) {
                    policyRetrievalPoint.clearUrlPoliciesCache();
                                    } else {
                    policyRetrievalPoint.clearMethodPoliciesCache();
                                    }
            } else {
                log.warn("PolicyRetrievalPoint not available - policy will be loaded on next request");
            }
        } catch (Exception e) {
            log.error("Failed to load policy to XACML engine: {}", policy.getId(), e);
        }
    }

    private void validatePolicyApplication(Policy policy) {
        try {
            
            if (!policy.getIsActive()) {
                log.warn("Policy {} is not active after creation", policy.getId());
            }

            if (policy.getRules().isEmpty()) {
                log.error("Policy {} has no rules after creation", policy.getId());
            }

            if (policy.getTargets().isEmpty()) {
                log.warn("Policy {} has no targets after creation", policy.getId());
            }

            List<Policy> existingPolicies = policyRepository.findAll().stream()
                .filter(p -> p.getName().equals(policy.getName()) && p.getIsActive())
                .toList();
            if (existingPolicies.size() > 1) {
                log.warn("Multiple active policies with same name: {}", policy.getName());
            }

        } catch (Exception e) {
            log.error("Policy validation failed for policy: {}", policy.getId(), e);
        }
    }

    private String getTargetType(Policy policy) {
        return policy.getTargets().stream()
            .findFirst()
            .map(PolicyTarget::getTargetType)
            .orElse("METHOD");
    }
}