package io.contexa.autoconfigure.enterprise.autonomous;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexaiam.domain.dto.ConditionDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.dto.RuleDto;
import io.contexa.contexaiam.domain.dto.TargetDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;


@Slf4j
public class ProposalToPolicyConverter {

    private static final String POLICY_NAME_PREFIX = "AI_EVOLVED_";
    private static final int DEFAULT_PRIORITY = 500;
    private static final int MIN_PRIORITY = 100;
    private static final int MAX_PRIORITY = 900;

    
    public PolicyDto convert(PolicyEvolutionProposal proposal) {
        if (proposal == null) {
            throw new IllegalArgumentException("PolicyEvolutionProposal cannot be null");
        }

        validateProposal(proposal);


        return PolicyDto.builder()
                .name(generatePolicyName(proposal))
                .description(generateDescription(proposal))
                .effect(determineEffect(proposal))
                .priority(calculatePriority(proposal))
                .targets(extractTargets(proposal))
                .rules(extractRules(proposal))
                .build();
    }

    
    private void validateProposal(PolicyEvolutionProposal proposal) {
        if (!StringUtils.hasText(proposal.getTitle())) {
            throw new IllegalArgumentException("Policy proposal title is required: proposalId=" + proposal.getId());
        }

        
        if (!StringUtils.hasText(proposal.getSpelExpression())
                && !StringUtils.hasText(proposal.getPolicyContent())) {
            throw new IllegalArgumentException(
                    "Policy proposal requires spelExpression or policyContent: proposalId=" + proposal.getId());
        }
    }

    
    private String generatePolicyName(PolicyEvolutionProposal proposal) {
        String typeSuffix = proposal.getProposalType() != null
                ? proposal.getProposalType().name()
                : "UNKNOWN";

        
        String sanitizedTitle = sanitizeForPolicyName(proposal.getTitle());

        return String.format("%s%s_%d_%s",
                POLICY_NAME_PREFIX,
                typeSuffix,
                proposal.getId(),
                sanitizedTitle);
    }

    
    private String sanitizeForPolicyName(String input) {
        if (!StringUtils.hasText(input)) {
            return "UNNAMED";
        }

        
        String sanitized = input.replaceAll("[^a-zA-Z0-9_가-힣]", "_");

        
        sanitized = sanitized.replaceAll("_+", "_");

        
        sanitized = sanitized.replaceAll("^_|_$", "");

        
        if (sanitized.length() > 30) {
            sanitized = sanitized.substring(0, 30);
        }

        return sanitized.isEmpty() ? "UNNAMED" : sanitized;
    }

    
    private String generateDescription(PolicyEvolutionProposal proposal) {
        StringBuilder description = new StringBuilder();

        
        description.append("[AI Generated Policy] ");

        if (StringUtils.hasText(proposal.getDescription())) {
            description.append(proposal.getDescription());
        } else {
            description.append(proposal.getTitle());
        }

        
        if (StringUtils.hasText(proposal.getAiReasoning())) {
            description.append("\n\n[AI Reasoning Basis]\n");
            String reasoning = proposal.getAiReasoning();
            
            if (reasoning.length() > 500) {
                reasoning = reasoning.substring(0, 497) + "...";
            }
            description.append(reasoning);
        }

        
        if (proposal.getConfidenceScore() != null) {
            description.append(String.format("\n\n[Confidence: %.1f%%]", proposal.getConfidenceScore() * 100));
        }

        
        description.append(String.format("\n\n[Original Proposal ID: %d]", proposal.getId()));

        return description.toString();
    }

    
    private Policy.Effect determineEffect(PolicyEvolutionProposal proposal) {
        if (proposal.getProposalType() == null) {
            return Policy.Effect.ALLOW;
        }

        
        Map<String, Object> metadata = proposal.getMetadata();
        if (metadata != null && metadata.containsKey("effect")) {
            String effectStr = String.valueOf(metadata.get("effect")).toUpperCase();
            try {
                return Policy.Effect.valueOf(effectStr);
            } catch (IllegalArgumentException e) {
                log.warn("Invalid effect value, using default: {}", effectStr);
            }
        }

        
        switch (proposal.getProposalType()) {
            case REVOKE_ACCESS:
            case DELETE_POLICY:
            case THREAT_RESPONSE:
            case INCIDENT_RESPONSE:
            case DATA_PROTECTION:
                return Policy.Effect.DENY;

            case GRANT_ACCESS:
            case CREATE_POLICY:
            case UPDATE_POLICY:
            case OPTIMIZE_RULE:
            case COMPLIANCE:
            case OPTIMIZATION:
            default:
                return Policy.Effect.ALLOW;
        }
    }

    
    private int calculatePriority(PolicyEvolutionProposal proposal) {
        int priority = DEFAULT_PRIORITY;

        
        if (proposal.getConfidenceScore() != null) {
            
            double confidenceAdjustment = (1 - proposal.getConfidenceScore()) * 200 - 100;
            priority += (int) confidenceAdjustment;
        }

        
        if (proposal.getRiskLevel() != null) {
            switch (proposal.getRiskLevel()) {
                case CRITICAL:
                    priority -= 100; 
                    break;
                case HIGH:
                    priority -= 50;
                    break;
                case MEDIUM:
                    
                    break;
                case LOW:
                    priority += 50; 
                    break;
            }
        }

        
        return Math.max(MIN_PRIORITY, Math.min(MAX_PRIORITY, priority));
    }

    
    private List<TargetDto> extractTargets(PolicyEvolutionProposal proposal) {
        List<TargetDto> targets = new ArrayList<>();

        Map<String, Object> context = proposal.getEvidenceContext();
        Map<String, Object> actionPayload = proposal.getActionPayload();
        Map<String, Object> metadata = proposal.getMetadata();

        
        String targetResource = extractStringValue(context, "targetResource", "targetUri", "resource");
        String httpMethod = extractStringValue(context, "requestMethod", "httpMethod", "method");
        String targetType = extractStringValue(context, "targetType", "resourceType");

        
        if (targetResource == null) {
            targetResource = extractStringValue(actionPayload, "targetResource", "resource");
        }
        if (httpMethod == null) {
            httpMethod = extractStringValue(actionPayload, "requestMethod", "httpMethod");
        }

        
        if (targetResource == null) {
            targetResource = extractStringValue(metadata, "targetResource", "resource");
        }

        
        if (StringUtils.hasText(targetResource)) {
            TargetDto target = TargetDto.builder()
                    .targetType(StringUtils.hasText(targetType) ? targetType : "URL")
                    .targetIdentifier(targetResource)
                    .httpMethod(StringUtils.hasText(httpMethod) ? httpMethod.toUpperCase() : "ALL")
                    .build();
            targets.add(target);

        } else {
            
            log.warn("No Target info, creating default target: proposalId={}", proposal.getId());
            TargetDto defaultTarget = TargetDto.builder()
                    .targetType("URL")
                    .targetIdentifier("/**")
                    .httpMethod("ALL")
                    .build();
            targets.add(defaultTarget);
        }

        return targets;
    }

    
    private List<RuleDto> extractRules(PolicyEvolutionProposal proposal) {
        List<RuleDto> rules = new ArrayList<>();

        
        String spelExpression = proposal.getSpelExpression();
        if (!StringUtils.hasText(spelExpression)) {
            spelExpression = proposal.getPolicyContent();
        }

        if (!StringUtils.hasText(spelExpression)) {
            log.warn("No SpEL expression, creating default rule: proposalId={}", proposal.getId());
            spelExpression = "isAuthenticated()";
        }

        
        List<ConditionDto> conditions = new ArrayList<>();
        ConditionDto condition = ConditionDto.builder()
                .expression(spelExpression)
                .authorizationPhase(PolicyCondition.AuthorizationPhase.PRE_AUTHORIZE)
                .build();
        conditions.add(condition);

        
        String ruleDescription = generateRuleDescription(proposal);

        
        RuleDto rule = RuleDto.builder()
                .description(ruleDescription)
                .conditions(conditions)
                .build();
        rules.add(rule);

        return rules;
    }

    
    private String generateRuleDescription(PolicyEvolutionProposal proposal) {
        StringBuilder description = new StringBuilder();

        description.append("AI Automatically Generated Rule");

        if (proposal.getProposalType() != null) {
            description.append(" [Type: ").append(proposal.getProposalType().name()).append("]");
        }

        if (proposal.getLearningType() != null) {
            description.append(" [Learning: ").append(proposal.getLearningType().name()).append("]");
        }

        if (proposal.getSourceEventId() != null) {
            description.append(" [Event: ").append(proposal.getSourceEventId()).append("]");
        }

        return description.toString();
    }

    
    private String extractStringValue(Map<String, Object> map, String... keys) {
        if (map == null) {
            return null;
        }

        for (String key : keys) {
            Object value = map.get(key);
            if (value != null && StringUtils.hasText(String.valueOf(value))) {
                return String.valueOf(value);
            }
        }

        return null;
    }

    
    public PolicyDto convertForUpdate(PolicyEvolutionProposal proposal, Long existingPolicyId) {
        PolicyDto policyDto = convert(proposal);
        policyDto.setId(existingPolicyId);

        return policyDto;
    }
}
