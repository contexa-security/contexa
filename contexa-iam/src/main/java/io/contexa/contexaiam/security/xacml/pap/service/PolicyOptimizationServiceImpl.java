package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexaiam.domain.dto.ConditionDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.dto.RuleDto;
import io.contexa.contexaiam.domain.dto.TargetDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@RequiredArgsConstructor
@Transactional(readOnly = true)
public class PolicyOptimizationServiceImpl implements PolicyOptimizationService {

    private final PolicyRepository policyRepository;
    private final ModelMapper modelMapper;

    
    @Override
    public List<DuplicatePolicyDto> findDuplicatePolicies() {
        List<Policy> policies = policyRepository.findAllWithDetails();

        
        Map<String, List<Long>> signatureMap = policies.stream()
                .collect(Collectors.groupingBy(
                        this::createPolicySignature,
                        Collectors.mapping(Policy::getId, Collectors.toList())
                ));

        
        return signatureMap.entrySet().stream()
                .filter(entry -> entry.getValue().size() > 1)
                
                .map(entry -> new DuplicatePolicyDto("동일한 대상과 규칙을 가진 중복 정책", entry.getValue(), entry.getKey()))
                .collect(Collectors.toList());
    }

    
    private String createPolicySignature(Policy policy) {
        
        String effect = policy.getEffect().name();

        
        String targets = policy.getTargets().stream()
                .map(t -> t.getTargetType() + ":" + t.getTargetIdentifier() + ":" + t.getHttpMethod())
                .sorted()
                .collect(Collectors.joining(","));

        
        String conditions = policy.getRules().stream()
                .flatMap(rule -> rule.getConditions().stream())
                .map(PolicyCondition::getExpression)
                .sorted()
                .collect(Collectors.joining("&&"));

        return String.join("|", effect, targets, conditions);
    }

    
    @Override
    public PolicyDto proposeMerge(List<Long> policyIds) {
        if (CollectionUtils.isEmpty(policyIds) || policyIds.size() < 2) {
            throw new IllegalArgumentException("병합하려면 두 개 이상의 정책이 필요합니다.");
        }
        List<Policy> policiesToMerge = policyRepository.findAllById(policyIds);
        if (policiesToMerge.size() != policyIds.size()) {
            throw new IllegalArgumentException("일부 정책을 찾을 수 없습니다.");
        }

        Policy firstPolicy = policiesToMerge.getFirst();
        String commonTargetSignature = createTargetSignature(firstPolicy);
        Policy.Effect commonEffect = firstPolicy.getEffect();

        for (Policy policy : policiesToMerge) {
            if (!commonEffect.equals(policy.getEffect()) || !commonTargetSignature.equals(createTargetSignature(policy))) {
                throw new IllegalArgumentException("대상 또는 효과가 다른 정책들은 병합할 수 없습니다.");
            }
        }

        String mergedCondition = policiesToMerge.stream()
                .flatMap(p -> p.getRules().stream())
                .flatMap(r -> r.getConditions().stream())
                .map(PolicyCondition::getExpression)
                .map(expr -> "(" + expr + ")")
                .distinct()
                .collect(Collectors.joining(" or "));

        
        
        ConditionDto mergedConditionDto = ConditionDto.builder()
                .expression(mergedCondition)
                .authorizationPhase(PolicyCondition.AuthorizationPhase.PRE_AUTHORIZE)
                .build();

        
        RuleDto mergedRule = RuleDto.builder()
                .description("ID " + policyIds + " 정책들로부터 병합됨")
                .conditions(List.of(mergedConditionDto))
                .build();

        
        return PolicyDto.builder()
                .name("Merged-Policy-" + String.join("-", policyIds.stream().map(String::valueOf).toList()))
                .description("여러 정책이 하나로 병합되었습니다.")
                .effect(commonEffect)
                .priority(firstPolicy.getPriority())
                .targets(firstPolicy.getTargets().stream().map(t -> modelMapper.map(t, TargetDto.class)).toList())
                .rules(List.of(mergedRule))
                .build();
    }

    private String createTargetSignature(Policy policy) {
        return policy.getTargets().stream()
                .map(t -> t.getTargetType() + ":" + t.getTargetIdentifier())
                .sorted()
                .collect(Collectors.joining(","));
    }
}