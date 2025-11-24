package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexaiam.common.event.dto.PolicyChangedEvent;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.domain.dto.ConditionDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.dto.RuleDto;
import io.contexa.contexaiam.domain.dto.TargetDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Transactional
public class DefaultPolicyService implements PolicyService {

    private final PolicyRepository policyRepository;
    private final PolicyRetrievalPoint policyRetrievalPoint;
    private final CustomDynamicAuthorizationManager authorizationManager;
    private final PolicyEnrichmentService policyEnrichmentService;
    private final ModelMapper modelMapper;
    private final IntegrationEventBus eventBus;
    private final PermissionRepository permissionRepository;

    //SpEL 에서 hasAuthority('PERMISSION_NAME') 형태의 권한 이름을 추출하기 위한 정규표현식
    private static final Pattern AUTHORITY_PATTERN = Pattern.compile("hasAuthority\\('([^']*)'\\)");


    @Override
    @Transactional(readOnly = true)
    public List<Policy> getAllPolicies() {
        return policyRepository.findAllWithDetails();
    }

    @Override
    @Transactional(readOnly = true)
    public Policy findById(Long id) {
        return policyRepository.findByIdWithDetails(id)
                .orElseThrow(() -> new IllegalArgumentException("Policy not found with ID: " + id));
    }

    @Override
    public Policy createPolicy(PolicyDto policyDto) { // DTO를 받는 시그니처 유지
        Policy policy = convertDtoToEntity(policyDto);
        policyEnrichmentService.enrichPolicyWithFriendlyDescription(policy);
        Policy savedPolicy = policyRepository.save(policy);

        // [수정] 정책에 포함된 권한 ID를 추출하여 이벤트를 발행합니다.
        publishPolicyChangedEvent(savedPolicy);

        reloadAuthorizationSystem();
        log.info("Policy created and authorization system reloaded. Policy Name: {}", savedPolicy.getName());
        return savedPolicy;
    }

    @Override
    public void updatePolicy(PolicyDto policyDto) {
        Policy existingPolicy = findById(policyDto.getId());
        updateEntityFromDto(existingPolicy, policyDto); // 친화적 설명 생성 로직은 updateEntityFromDto 내부 또는 이후 호출
        policyEnrichmentService.enrichPolicyWithFriendlyDescription(existingPolicy);
        Policy updatedPolicy = policyRepository.save(existingPolicy);

        // [수정] 정책에 포함된 권한 ID를 추출하여 이벤트를 발행합니다.
        publishPolicyChangedEvent(updatedPolicy);

        reloadAuthorizationSystem();
        log.info("Policy updated and authorization system reloaded. Policy ID: {}", updatedPolicy.getId());
    }

    private void publishPolicyChangedEvent(Policy policy) {
        Set<String> permissionNames = new HashSet<>();
        policy.getRules().stream()
                .flatMap(rule -> rule.getConditions().stream())
                .map(PolicyCondition::getExpression)
                .forEach(spel -> {
                    Matcher matcher = AUTHORITY_PATTERN.matcher(spel);
                    while (matcher.find()) {
                        permissionNames.add(matcher.group(1));
                    }
                });

        if (!permissionNames.isEmpty()) {
            Set<Long> permissionIds = permissionRepository.findAllByNameIn(permissionNames).stream()
                    .map(Permission::getId)
                    .collect(Collectors.toSet());
            eventBus.publish(new PolicyChangedEvent(policy.getId(), permissionIds));
        }
    }

    @Override
    public void synchronizePolicyForPermission(Permission permission) {
        ManagedResource resource = permission.getManagedResource();
        if (resource == null) {
            log.warn("Permission '{}' has no linked resource. Cannot sync policy.", permission.getName());
            return;
        }

        String policyName = "AUTO_POLICY_FOR_PERM_" + permission.getName();
        String expression = String.format("hasAuthority('%s')", permission.getName());

        // 정책의 '명세'인 PolicyDto 생성
        PolicyDto policyDto = PolicyDto.builder()
                .name(policyName)
                .description(String.format("'%s' 권한에 대한 자동 생성 정책", permission.getFriendlyName()))
                .effect(Policy.Effect.ALLOW)
                .priority(500) // 자동 생성 정책은 중간 우선순위
                .targets(List.of(new TargetDto(
                        resource.getResourceType().name(),
                        resource.getResourceIdentifier(),
                        resource.getHttpMethod() != null ? resource.getHttpMethod().name() : "ANY"
                )))
                .rules(List.of(new RuleDto(
                        "Auto-generated rule for " + permission.getName(),
                        List.of(new ConditionDto(expression, PolicyCondition.AuthorizationPhase.PRE_AUTHORIZE))
                )))
                .build();

        // 기존 정책이 있는지 확인하여 ID 설정 (업데이트를 위함)
        policyRepository.findByName(policyName).ifPresent(p -> policyDto.setId(p.getId()));

        // DTO를 사용하여 정책 생성 또는 업데이트
        if (policyDto.getId() != null) {
            this.updatePolicy(policyDto);
        } else {
            this.createPolicy(policyDto);
        }
    }

    @Override
    public void deletePolicy(Long id) {
        policyRepository.deleteById(id);
        // 삭제 시에는 빈 권한 ID 목록으로 이벤트를 발행하여, 관련된 연결이 없음을 알릴 수 있습니다.
        eventBus.publish(new PolicyChangedEvent(id, new HashSet<>()));
        reloadAuthorizationSystem();
        log.info("Policy deleted and authorization system reloaded. Policy ID: {}", id);
    }

    /**
     * 정책 변경 후 인가 시스템을 다시 로드하는 중앙화된 메서드.
     */
    private void reloadAuthorizationSystem() {
        policyRetrievalPoint.clearUrlPoliciesCache();
        policyRetrievalPoint.clearMethodPoliciesCache(); // 메서드 정책 캐시도 클리어
        authorizationManager.reload();
    }

    // --- DTO <-> Entity 변환 헬퍼 메서드 ---
    private Policy convertDtoToEntity(PolicyDto dto) {
        Policy policy = Policy.builder()
                .name(dto.getName())
                .description(dto.getDescription())
                .effect(dto.getEffect())
                .priority(dto.getPriority())
                .build();

        // Target 파싱 로직 (안정성 강화)
        if (dto.getTargets() != null) {
            Set<PolicyTarget> targets = dto.getTargets().stream().map(targetDto ->
                    PolicyTarget.builder()
                            .policy(policy)
                            .targetType(targetDto.getTargetType())
                            .targetIdentifier(targetDto.getTargetIdentifier())
                            .httpMethod("ALL".equals(targetDto.getHttpMethod()) ? null : targetDto.getHttpMethod()) // "ALL"은 null로 저장
                            .build()
            ).collect(Collectors.toSet());
            policy.setTargets(targets);
        }

        // 여러 규칙(Rule)을 처리하는 로직
        if (dto.getRules() != null) {
            Set<PolicyRule> policyRules = dto.getRules().stream().map(ruleDto -> {
                PolicyRule rule = PolicyRule.builder().policy(policy).description(ruleDto.getDescription()).build();

                // [수정] ConditionDto를 순회하며 PolicyCondition 엔티티 생성
                Set<PolicyCondition> conditions = ruleDto.getConditions().stream()
                        .map(condDto -> PolicyCondition.builder()
                                .rule(rule)
                                .expression(condDto.getExpression())
                                .authorizationPhase(condDto.getAuthorizationPhase()) // phase 정보 추가
                                .build())
                        .collect(Collectors.toSet());

                rule.setConditions(conditions);
                return rule;
            }).collect(Collectors.toSet());
            policy.setRules(policyRules);
        }

        return policy;
    }

    private void updateEntityFromDto(Policy policy, PolicyDto dto) {
        policy.setName(dto.getName());
        policy.setDescription(dto.getDescription());
        policy.setEffect(dto.getEffect());
        policy.setPriority(dto.getPriority());

        // "clear and add all" 전략 사용
        policy.getTargets().clear();
        policy.getRules().clear();

        // Target 변환 로직
        if (dto.getTargets() != null) {
            dto.getTargets().forEach(targetDto -> {
                policy.getTargets().add(PolicyTarget.builder()
                        .policy(policy)
                        .targetType(targetDto.getTargetType())
                        .targetIdentifier(targetDto.getTargetIdentifier())
                        .httpMethod("ALL".equals(targetDto.getHttpMethod()) ? null : targetDto.getHttpMethod())
                        .build());
            });
        }

        // 여러 규칙(Rule)을 처리하는 로직
        if (dto.getRules() != null) {
            dto.getRules().forEach(ruleDto -> {
                PolicyRule rule = PolicyRule.builder()
                        .policy(policy)
                        .description(ruleDto.getDescription())
                        .build();

                Set<PolicyCondition> conditions = ruleDto.getConditions().stream()
                        .map(condition -> PolicyCondition.builder().rule(rule).expression(condition.getExpression()).build())
                        .collect(Collectors.toSet());

                rule.setConditions(conditions);
                policy.getRules().add(rule);
            });
        }
    }
}
