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

/**
 * PolicyEvolutionProposal을 XACML PAP의 PolicyDto로 변환하는 컨버터
 *
 * AI가 생성한 정책 제안(PolicyEvolutionProposal)을 Spring Security에서
 * 사용하는 정책(Policy)으로 변환합니다.
 *
 * 변환 매핑:
 * - proposal.title -> policy.name (접두사: AI_EVOLVED_)
 * - proposal.description -> policy.description
 * - proposal.spelExpression -> rule.conditions.expression
 * - proposal.evidenceContext -> target 정보 추출
 * - proposal.confidenceScore -> priority 계산
 *
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
public class ProposalToPolicyConverter {

    // 정책 이름 접두사
    private static final String POLICY_NAME_PREFIX = "AI_EVOLVED_";

    // 기본 우선순위 (AI 생성 정책은 수동 정책보다 낮은 우선순위)
    private static final int DEFAULT_PRIORITY = 500;

    // 최소/최대 우선순위
    private static final int MIN_PRIORITY = 100;
    private static final int MAX_PRIORITY = 900;

    /**
     * PolicyEvolutionProposal을 PolicyDto로 변환
     *
     * @param proposal AI가 생성한 정책 제안
     * @return XACML PAP에서 사용할 PolicyDto
     * @throws IllegalArgumentException proposal이 null이거나 필수 필드가 누락된 경우
     */
    public PolicyDto convert(PolicyEvolutionProposal proposal) {
        if (proposal == null) {
            throw new IllegalArgumentException("PolicyEvolutionProposal은 null일 수 없습니다");
        }

        validateProposal(proposal);

        log.info("PolicyEvolutionProposal을 PolicyDto로 변환 시작: proposalId={}, title={}",
                proposal.getId(), proposal.getTitle());

        PolicyDto policyDto = PolicyDto.builder()
                .name(generatePolicyName(proposal))
                .description(generateDescription(proposal))
                .effect(determineEffect(proposal))
                .priority(calculatePriority(proposal))
                .targets(extractTargets(proposal))
                .rules(extractRules(proposal))
                .build();

        log.info("PolicyDto 변환 완료: policyName={}, effect={}, priority={}, targetCount={}, ruleCount={}",
                policyDto.getName(), policyDto.getEffect(), policyDto.getPriority(),
                policyDto.getTargets().size(), policyDto.getRules().size());

        return policyDto;
    }

    /**
     * 제안 유효성 검증
     */
    private void validateProposal(PolicyEvolutionProposal proposal) {
        if (!StringUtils.hasText(proposal.getTitle())) {
            throw new IllegalArgumentException("정책 제안의 title은 필수입니다: proposalId=" + proposal.getId());
        }

        // SpEL 표현식 또는 policyContent 중 하나는 있어야 함
        if (!StringUtils.hasText(proposal.getSpelExpression())
                && !StringUtils.hasText(proposal.getPolicyContent())) {
            throw new IllegalArgumentException(
                    "정책 제안에는 spelExpression 또는 policyContent가 필요합니다: proposalId=" + proposal.getId());
        }
    }

    /**
     * 정책 이름 생성
     * 형식: AI_EVOLVED_{proposalType}_{proposalId}_{timestamp}
     */
    private String generatePolicyName(PolicyEvolutionProposal proposal) {
        String typeSuffix = proposal.getProposalType() != null
                ? proposal.getProposalType().name()
                : "UNKNOWN";

        // 제목에서 특수문자 제거하고 30자로 제한
        String sanitizedTitle = sanitizeForPolicyName(proposal.getTitle());

        return String.format("%s%s_%d_%s",
                POLICY_NAME_PREFIX,
                typeSuffix,
                proposal.getId(),
                sanitizedTitle);
    }

    /**
     * 정책 이름에 사용할 수 있도록 문자열 정제
     */
    private String sanitizeForPolicyName(String input) {
        if (!StringUtils.hasText(input)) {
            return "UNNAMED";
        }

        // 영문, 숫자, 언더스코어만 허용
        String sanitized = input.replaceAll("[^a-zA-Z0-9_가-힣]", "_");

        // 연속된 언더스코어 제거
        sanitized = sanitized.replaceAll("_+", "_");

        // 앞뒤 언더스코어 제거
        sanitized = sanitized.replaceAll("^_|_$", "");

        // 30자로 제한
        if (sanitized.length() > 30) {
            sanitized = sanitized.substring(0, 30);
        }

        return sanitized.isEmpty() ? "UNNAMED" : sanitized;
    }

    /**
     * 설명 생성
     */
    private String generateDescription(PolicyEvolutionProposal proposal) {
        StringBuilder description = new StringBuilder();

        // 기본 설명
        description.append("[AI 생성 정책] ");

        if (StringUtils.hasText(proposal.getDescription())) {
            description.append(proposal.getDescription());
        } else {
            description.append(proposal.getTitle());
        }

        // AI 추론 근거 추가
        if (StringUtils.hasText(proposal.getAiReasoning())) {
            description.append("\n\n[AI 추론 근거]\n");
            String reasoning = proposal.getAiReasoning();
            // 500자로 제한
            if (reasoning.length() > 500) {
                reasoning = reasoning.substring(0, 497) + "...";
            }
            description.append(reasoning);
        }

        // 신뢰도 정보 추가
        if (proposal.getConfidenceScore() != null) {
            description.append(String.format("\n\n[신뢰도: %.1f%%]", proposal.getConfidenceScore() * 100));
        }

        // 원본 제안 ID 참조
        description.append(String.format("\n\n[원본 제안 ID: %d]", proposal.getId()));

        return description.toString();
    }

    /**
     * 정책 효과(Effect) 결정
     * proposalType에 따라 ALLOW 또는 DENY 결정
     */
    private Policy.Effect determineEffect(PolicyEvolutionProposal proposal) {
        if (proposal.getProposalType() == null) {
            return Policy.Effect.ALLOW;
        }

        // metadata에서 effect가 명시적으로 지정된 경우 우선 사용
        Map<String, Object> metadata = proposal.getMetadata();
        if (metadata != null && metadata.containsKey("effect")) {
            String effectStr = String.valueOf(metadata.get("effect")).toUpperCase();
            try {
                return Policy.Effect.valueOf(effectStr);
            } catch (IllegalArgumentException e) {
                log.warn("잘못된 effect 값, 기본값 사용: {}", effectStr);
            }
        }

        // proposalType에 따른 기본 effect 결정
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

    /**
     * 우선순위 계산
     * confidenceScore가 높을수록 높은 우선순위 (낮은 숫자)
     * riskLevel이 높을수록 높은 우선순위 (낮은 숫자)
     */
    private int calculatePriority(PolicyEvolutionProposal proposal) {
        int priority = DEFAULT_PRIORITY;

        // 신뢰도 기반 조정 (-100 ~ +100)
        if (proposal.getConfidenceScore() != null) {
            // 높은 신뢰도 = 낮은 우선순위 값 = 높은 우선순위
            double confidenceAdjustment = (1 - proposal.getConfidenceScore()) * 200 - 100;
            priority += (int) confidenceAdjustment;
        }

        // 위험도 기반 조정
        if (proposal.getRiskLevel() != null) {
            switch (proposal.getRiskLevel()) {
                case CRITICAL:
                    priority -= 100; // 높은 우선순위
                    break;
                case HIGH:
                    priority -= 50;
                    break;
                case MEDIUM:
                    // 기본값 유지
                    break;
                case LOW:
                    priority += 50; // 낮은 우선순위
                    break;
            }
        }

        // 범위 제한
        return Math.max(MIN_PRIORITY, Math.min(MAX_PRIORITY, priority));
    }

    /**
     * 대상(Target) 추출
     * evidenceContext에서 targetResource, requestMethod 정보를 추출
     */
    private List<TargetDto> extractTargets(PolicyEvolutionProposal proposal) {
        List<TargetDto> targets = new ArrayList<>();

        Map<String, Object> context = proposal.getEvidenceContext();
        Map<String, Object> actionPayload = proposal.getActionPayload();
        Map<String, Object> metadata = proposal.getMetadata();

        // evidenceContext에서 target 정보 추출
        String targetResource = extractStringValue(context, "targetResource", "targetUri", "resource");
        String httpMethod = extractStringValue(context, "requestMethod", "httpMethod", "method");
        String targetType = extractStringValue(context, "targetType", "resourceType");

        // actionPayload에서 추가 target 정보 추출
        if (targetResource == null) {
            targetResource = extractStringValue(actionPayload, "targetResource", "resource");
        }
        if (httpMethod == null) {
            httpMethod = extractStringValue(actionPayload, "requestMethod", "httpMethod");
        }

        // metadata에서 target 정보 추출
        if (targetResource == null) {
            targetResource = extractStringValue(metadata, "targetResource", "resource");
        }

        // target 정보가 있으면 TargetDto 생성
        if (StringUtils.hasText(targetResource)) {
            TargetDto target = TargetDto.builder()
                    .targetType(StringUtils.hasText(targetType) ? targetType : "URL")
                    .targetIdentifier(targetResource)
                    .httpMethod(StringUtils.hasText(httpMethod) ? httpMethod.toUpperCase() : "ALL")
                    .build();
            targets.add(target);

            log.debug("Target 추출: type={}, identifier={}, method={}",
                    target.getTargetType(), target.getTargetIdentifier(), target.getHttpMethod());
        } else {
            // 기본 target 생성 (모든 리소스에 적용)
            log.warn("Target 정보 없음, 기본 target 생성: proposalId={}", proposal.getId());
            TargetDto defaultTarget = TargetDto.builder()
                    .targetType("URL")
                    .targetIdentifier("/**")
                    .httpMethod("ALL")
                    .build();
            targets.add(defaultTarget);
        }

        return targets;
    }

    /**
     * 규칙(Rule) 추출
     * spelExpression 또는 policyContent를 Rule로 변환
     */
    private List<RuleDto> extractRules(PolicyEvolutionProposal proposal) {
        List<RuleDto> rules = new ArrayList<>();

        // SpEL 표현식 가져오기 (spelExpression 우선, 없으면 policyContent)
        String spelExpression = proposal.getSpelExpression();
        if (!StringUtils.hasText(spelExpression)) {
            spelExpression = proposal.getPolicyContent();
        }

        if (!StringUtils.hasText(spelExpression)) {
            log.warn("SpEL 표현식 없음, 기본 규칙 생성: proposalId={}", proposal.getId());
            spelExpression = "isAuthenticated()";
        }

        // 조건 생성
        List<ConditionDto> conditions = new ArrayList<>();
        ConditionDto condition = ConditionDto.builder()
                .expression(spelExpression)
                .authorizationPhase(PolicyCondition.AuthorizationPhase.PRE_AUTHORIZE)
                .build();
        conditions.add(condition);

        // 규칙 설명 생성
        String ruleDescription = generateRuleDescription(proposal);

        // 규칙 생성
        RuleDto rule = RuleDto.builder()
                .description(ruleDescription)
                .conditions(conditions)
                .build();
        rules.add(rule);

        log.debug("Rule 추출: description={}, conditionCount={}, spelExpression={}",
                rule.getDescription(), conditions.size(),
                spelExpression.length() > 50 ? spelExpression.substring(0, 50) + "..." : spelExpression);

        return rules;
    }

    /**
     * 규칙 설명 생성
     */
    private String generateRuleDescription(PolicyEvolutionProposal proposal) {
        StringBuilder description = new StringBuilder();

        description.append("AI 자동 생성 규칙");

        if (proposal.getProposalType() != null) {
            description.append(" [유형: ").append(proposal.getProposalType().name()).append("]");
        }

        if (proposal.getLearningType() != null) {
            description.append(" [학습: ").append(proposal.getLearningType().name()).append("]");
        }

        if (proposal.getSourceEventId() != null) {
            description.append(" [이벤트: ").append(proposal.getSourceEventId()).append("]");
        }

        return description.toString();
    }

    /**
     * Map에서 여러 가능한 키로 문자열 값 추출
     */
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

    /**
     * 기존 정책 업데이트를 위한 변환 (ID 포함)
     *
     * @param proposal AI가 생성한 정책 제안
     * @param existingPolicyId 기존 정책 ID
     * @return 업데이트용 PolicyDto
     */
    public PolicyDto convertForUpdate(PolicyEvolutionProposal proposal, Long existingPolicyId) {
        PolicyDto policyDto = convert(proposal);
        policyDto.setId(existingPolicyId);

        log.info("기존 정책 업데이트용 PolicyDto 생성: policyId={}, proposalId={}",
                existingPolicyId, proposal.getId());

        return policyDto;
    }
}
