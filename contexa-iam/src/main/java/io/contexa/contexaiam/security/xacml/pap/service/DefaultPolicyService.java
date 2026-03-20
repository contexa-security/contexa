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
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
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
    private final IntegrationEventBus eventBus;
    private final PermissionRepository permissionRepository;
    private final ManagedResourceRepository managedResourceRepository;

    private static final Pattern AUTHORITY_PATTERN = Pattern.compile("hasAuthority\\('([^']*)'\\)");

    @Override
    @Transactional(readOnly = true)
    public List<Policy> getAllPolicies() {
        return policyRepository.findAllWithDetails();
    }

    @Override
    @Transactional(readOnly = true)
    public Page<Policy> searchPolicies(String keyword, Pageable pageable) {
        return policyRepository.searchByKeyword(keyword, pageable);
    }

    @Override
    @Transactional(readOnly = true)
    public Policy findById(Long id) {
        return policyRepository.findByIdWithDetails(id)
                .orElseThrow(() -> new IllegalArgumentException("Policy not found with ID: " + id));
    }

    @Override
    public Policy createPolicy(PolicyDto policyDto) { 
        Policy policy = convertDtoToEntity(policyDto);
        policyEnrichmentService.enrichPolicyWithFriendlyDescription(policy);
        Policy savedPolicy = policyRepository.save(policy);

        publishPolicyChangedEvent(savedPolicy);

        reloadAuthorizationSystem();
                return savedPolicy;
    }

    @Override
    public void updatePolicy(PolicyDto policyDto) {
        Policy existingPolicy = findById(policyDto.getId());
        updateEntityFromDto(existingPolicy, policyDto); 
        policyEnrichmentService.enrichPolicyWithFriendlyDescription(existingPolicy);
        Policy updatedPolicy = policyRepository.save(existingPolicy);

        publishPolicyChangedEvent(updatedPolicy);

        reloadAuthorizationSystem();
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
            log.error("Permission '{}' has no linked resource. Cannot sync policy.", permission.getName());
            return;
        }

        String policyName = "AUTO_POLICY_FOR_PERM_" + permission.getName();
        String expression = String.format("hasAuthority('%s')", permission.getName());

        PolicyDto policyDto = PolicyDto.builder()
                .name(policyName)
                .description(String.format("Auto-generated policy for permission '%s'", permission.getFriendlyName()))
                .effect(Policy.Effect.ALLOW)
                .priority(500) 
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

        policyRepository.findByName(policyName).ifPresent(p -> policyDto.setId(p.getId()));

        if (policyDto.getId() != null) {
            this.updatePolicy(policyDto);
        } else {
            this.createPolicy(policyDto);
        }
    }

    @Override
    public void deletePolicy(Long id) {
        // Revert connected resources to PERMISSION_CREATED before deleting
        policyRepository.findByIdWithDetails(id).ifPresent(policy -> {
            Set<String> permNames = new HashSet<>();
            policy.getRules().stream()
                    .flatMap(rule -> rule.getConditions().stream())
                    .map(PolicyCondition::getExpression)
                    .forEach(spel -> {
                        Matcher matcher = AUTHORITY_PATTERN.matcher(spel);
                        while (matcher.find()) permNames.add(matcher.group(1));
                    });
            if (!permNames.isEmpty()) {
                permissionRepository.findAllByNameIn(permNames).forEach(perm -> {
                    ManagedResource resource = perm.getManagedResource();
                    if (resource != null && resource.getStatus() == ManagedResource.Status.POLICY_CONNECTED) {
                        resource.setStatus(ManagedResource.Status.PERMISSION_CREATED);
                        managedResourceRepository.save(resource);
                    }
                });
            }
        });

        policyRepository.deleteById(id);

        eventBus.publish(new PolicyChangedEvent(id, new HashSet<>()));
        reloadAuthorizationSystem();
            }

    private void reloadAuthorizationSystem() {
        policyRetrievalPoint.clearUrlPoliciesCache();
        policyRetrievalPoint.clearMethodPoliciesCache(); 
        authorizationManager.reload();
    }

    private Policy convertDtoToEntity(PolicyDto dto) {
        Policy policy = Policy.builder()
                .name(dto.getName())
                .description(dto.getDescription())
                .effect(dto.getEffect())
                .priority(dto.getPriority())
                .build();

        if (dto.getTargets() != null) {
            Set<PolicyTarget> targets = dto.getTargets().stream().map(targetDto ->
                    PolicyTarget.builder()
                            .policy(policy)
                            .targetType(targetDto.getTargetType())
                            .targetIdentifier(targetDto.getTargetIdentifier())
                            .httpMethod("ALL".equals(targetDto.getHttpMethod()) ? null : targetDto.getHttpMethod()) 
                            .build()
            ).collect(Collectors.toSet());
            policy.setTargets(targets);
        }

        if (dto.getRules() != null) {
            Set<PolicyRule> policyRules = dto.getRules().stream().map(ruleDto -> {
                PolicyRule rule = PolicyRule.builder().policy(policy).description(ruleDto.getDescription()).build();

                Set<PolicyCondition> conditions = ruleDto.getConditions().stream()
                        .map(condDto -> PolicyCondition.builder()
                                .rule(rule)
                                .expression(condDto.getExpression())
                                .authorizationPhase(condDto.getAuthorizationPhase()) 
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

        policy.getTargets().clear();
        policy.getRules().clear();

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

        if (dto.getRules() != null) {
            dto.getRules().forEach(ruleDto -> {
                PolicyRule rule = PolicyRule.builder()
                        .policy(policy)
                        .description(ruleDto.getDescription())
                        .build();

                Set<PolicyCondition> conditions = ruleDto.getConditions().stream()
                        .map(condition -> PolicyCondition.builder().rule(rule).expression(condition.getExpression()).authorizationPhase(condition.getAuthorizationPhase()).build())
                        .collect(Collectors.toSet());

                rule.setConditions(conditions);
                policy.getRules().add(rule);
            });
        }
    }
}
