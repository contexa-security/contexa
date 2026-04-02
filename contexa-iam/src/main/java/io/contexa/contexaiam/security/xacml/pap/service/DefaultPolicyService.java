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
import io.contexa.contexaiam.domain.entity.policy.PolicyVersion;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.analysis.AIPolicyValidator;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyConflictAnalyzer;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyConflictException;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyImpactAnalyzer;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicySimulator;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.dto.AIPolicyValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyImpactReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationTestCase;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexacore.infra.redis.PolicyReloadBroadcaster;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
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
    private final CentralAuditFacade centralAuditFacade;
    private final PolicyConflictAnalyzer policyConflictAnalyzer;
    private final PolicyValidationService policyValidationService;
    private final PolicyVersionService policyVersionService;
    private final PolicyImpactAnalyzer policyImpactAnalyzer;
    private final PolicySimulator policySimulator;
    private final AIPolicyValidator aiPolicyValidator;

    @Setter
    private PolicyReloadBroadcaster policyReloadBroadcaster;

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
    public Page<Policy> searchPolicies(String keyword, Policy.ApprovalStatus approvalStatus, Boolean activeFilter, Pageable pageable) {
        return policyRepository.searchByFilters(keyword, approvalStatus, activeFilter, pageable);
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
        validateConflicts(policy);
        policyEnrichmentService.enrichPolicyWithFriendlyDescription(policy);
        Policy savedPolicy = policyRepository.save(policy);

        policyVersionService.createVersion(savedPolicy,
                PolicyVersion.ChangeType.CREATED, policyDto.getChangeReason());

        publishPolicyChangedEvent(savedPolicy);
        auditPolicyChange(AuditEventCategory.POLICY_CREATED, savedPolicy);

        reloadAuthorizationSystem();
        return savedPolicy;
    }

    @Override
    public void updatePolicy(PolicyDto policyDto) {
        Policy existingPolicy = findById(policyDto.getId());
        policyVersionService.createVersion(existingPolicy,
                PolicyVersion.ChangeType.UPDATED, policyDto.getChangeReason());

        updateEntityFromDto(existingPolicy, policyDto);
        validateConflicts(existingPolicy);
        policyEnrichmentService.enrichPolicyWithFriendlyDescription(existingPolicy);
        Policy updatedPolicy = policyRepository.save(existingPolicy);

        publishPolicyChangedEvent(updatedPolicy);
        auditPolicyChange(AuditEventCategory.POLICY_UPDATED, updatedPolicy);

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
                .targets(List.of(TargetDto.builder()
                        .targetType(resource.getResourceType().name())
                        .targetIdentifier(resource.getResourceIdentifier())
                        .httpMethod(resource.getHttpMethod() != null ? resource.getHttpMethod().name() : "ANY")
                        .build()))
                .rules(List.of(new RuleDto(
                        "Auto-generated rule for " + permission.getName(),
                        List.of(new ConditionDto(expression, PolicyCondition.AuthorizationPhase.PRE_AUTHORIZE))
                )))
                .build();

        policyRepository.findByName(policyName).ifPresent(p -> policyDto.setId(p.getId()));

        try {
            if (policyDto.getId() != null) {
                this.updatePolicy(policyDto);
            } else {
                this.createPolicy(policyDto);
            }
        } catch (PolicyConflictException e) {
            log.error("Auto-policy sync blocked by conflict for permission '{}': {}",
                    permission.getName(), e.getMessage());
            centralAuditFacade.recordAsync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.POLICY_CREATED)
                    .principalName("SYSTEM")
                    .resourceIdentifier(policyName)
                    .eventSource("IAM")
                    .action("AUTO_POLICY_SYNC_BLOCKED")
                    .decision("BLOCKED")
                    .outcome("CONFLICT")
                    .reason(e.getMessage())
                    .build());
        }
    }

    @Override
    public void deletePolicy(Long id) {
        deletePolicy(id, null);
    }

    @Override
    public void deletePolicy(Long id, String changeReason) {
        // Version snapshot before delete
        policyRepository.findByIdWithDetails(id).ifPresent(policy ->
                policyVersionService.createVersion(policy,
                        PolicyVersion.ChangeType.DELETED, changeReason));

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
                        long otherPolicyCount = policyRepository.countOtherPoliciesForTarget(
                                resource.getResourceType().name(),
                                resource.getResourceIdentifier(),
                                id);
                        if (otherPolicyCount == 0) {
                            resource.setStatus(ManagedResource.Status.PERMISSION_CREATED);
                            managedResourceRepository.save(resource);
                        }
                    }
                });
            }
        });

        // Audit before delete
        policyRepository.findById(id).ifPresent(p ->
                auditPolicyChange(AuditEventCategory.POLICY_DELETED, p));

        policyRepository.deleteById(id);

        eventBus.publish(new PolicyChangedEvent(id, new HashSet<>()));
        reloadAuthorizationSystem();
            }

    @Override
    public void approvePolicy(Long id, String approver) {
        Policy policy = findById(id);
        if (policy.getApprovalStatus() == Policy.ApprovalStatus.APPROVED) {
            throw new IllegalStateException("Policy is already approved.");
        }

        if (policy.isAIGenerated()) {
            AIPolicyValidationReport validationReport = aiPolicyValidator.validate(policy);
            if (!validationReport.canApprove()) {
                throw new IllegalStateException(
                        "AI policy validation failed: " + validationReport.blockedReason());
            }
        }

        policy.approve(approver);
        policyRepository.save(policy);
        auditPolicyChange(AuditEventCategory.POLICY_UPDATED, policy);
        reloadAuthorizationSystem();
    }

    @Override
    public void rejectPolicy(Long id, String rejector) {
        Policy policy = findById(id);
        if (policy.getApprovalStatus() == Policy.ApprovalStatus.REJECTED) {
            throw new IllegalStateException("Policy is already rejected.");
        }
        policy.reject(rejector);
        policyRepository.save(policy);
        auditPolicyChange(AuditEventCategory.POLICY_UPDATED, policy);
        reloadAuthorizationSystem();
    }

    @Override
    @Transactional(readOnly = true)
    public List<PolicyConflictDto> detectConflicts(PolicyDto policyDto) {
        Policy policy = convertDtoToEntity(policyDto);
        if (policyDto.getId() != null) {
            policy.setId(policyDto.getId());
        }
        return policyConflictAnalyzer.analyze(policy);
    }

    @Override
    @Transactional(readOnly = true)
    public List<PolicyVersion> getVersions(Long policyId) {
        return policyVersionService.getVersions(policyId);
    }

    @Override
    public Policy rollbackPolicy(Long policyId, int versionNumber, String reason) {
        PolicyVersion version = policyVersionService.getVersion(policyId, versionNumber)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Version " + versionNumber + " not found for policy " + policyId));

        PolicyDto snapshotDto = policyVersionService.deserializeSnapshot(version)
                .orElseThrow(() -> new IllegalStateException(
                        "Failed to deserialize snapshot for version " + versionNumber));

        String rollbackReason = "Rollback to version " + versionNumber
                + (reason != null ? ": " + reason : "");

        Policy existingPolicy = findById(policyId);
        updateEntityFromDto(existingPolicy, snapshotDto);
        validateConflicts(existingPolicy);
        policyEnrichmentService.enrichPolicyWithFriendlyDescription(existingPolicy);
        Policy savedPolicy = policyRepository.save(existingPolicy);

        policyVersionService.createVersion(savedPolicy,
                PolicyVersion.ChangeType.ROLLBACK, rollbackReason);

        publishPolicyChangedEvent(savedPolicy);
        auditPolicyChange(AuditEventCategory.POLICY_UPDATED, savedPolicy);
        reloadAuthorizationSystem();

        return savedPolicy;
    }

    @Override
    @Transactional(readOnly = true)
    public PolicyValidationReport validateBeforeCreate(PolicyDto policyDto) {
        Policy policy = convertDtoToEntity(policyDto);
        if (policyDto.getId() != null) {
            policy.setId(policyDto.getId());
        }
        return policyValidationService.validate(policy);
    }

    @Override
    @Transactional(readOnly = true)
    public PolicyImpactReport analyzeImpact(PolicyDto policyDto) {
        Policy policy = convertDtoToEntity(policyDto);
        if (policyDto.getId() != null) {
            policy.setId(policyDto.getId());
        }
        return policyImpactAnalyzer.analyze(policy);
    }

    @Override
    @Transactional(readOnly = true)
    public AIPolicyValidationReport validateAIPolicy(Long policyId) {
        Policy policy = findById(policyId);
        return aiPolicyValidator.validate(policy);
    }

    @Override
    @Transactional(readOnly = true)
    public SimulationReport simulate(PolicyDto candidatePolicy, List<SimulationTestCase> testCases) {
        Policy candidate = null;
        if (candidatePolicy != null) {
            candidate = convertDtoToEntity(candidatePolicy);
            if (candidatePolicy.getId() != null) {
                candidate.setId(candidatePolicy.getId());
            }
        }
        return policySimulator.simulate(candidate, testCases);
    }

    private void validateConflicts(Policy policy) {
        List<PolicyConflictDto> conflicts = policyConflictAnalyzer.analyze(policy);
        List<PolicyConflictDto> criticalConflicts = conflicts.stream()
                .filter(c -> c.severity() == PolicyConflictDto.Severity.CRITICAL)
                .toList();
        if (!criticalConflicts.isEmpty()) {
            String details = criticalConflicts.stream()
                    .map(c -> String.format("[%s] %s", c.existingPolicyName(), c.conflictDescription()))
                    .collect(Collectors.joining("; "));
            throw new PolicyConflictException(
                    "Critical policy conflicts detected: " + details, conflicts);
        }
        if (!conflicts.isEmpty()) {
            log.error("Policy conflicts detected for '{}': {}", policy.getName(),
                    conflicts.stream().map(PolicyConflictDto::conflictDescription).collect(Collectors.joining("; ")));
        }
    }

    private void auditPolicyChange(AuditEventCategory category, Policy policy) {
        try {
            String principal = "SYSTEM";
            var auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getName() != null) principal = auth.getName();

            centralAuditFacade.recordAsync(AuditRecord.builder()
                    .eventCategory(category)
                    .principalName(principal)
                    .resourceIdentifier(policy.getName() != null ? policy.getName() : "")
                    .eventSource("IAM")
                    .action(category.name())
                    .decision("SUCCESS")
                    .outcome("SUCCESS")
                    .details(Map.of(
                            "policyId", policy.getId() != null ? policy.getId() : 0L,
                            "policyName", policy.getName() != null ? policy.getName() : "",
                            "effect", policy.getEffect() != null ? policy.getEffect().name() : "",
                            "source", policy.getSource() != null ? policy.getSource().name() : ""))
                    .build());
        } catch (Exception e) {
            log.error("Failed to audit policy change: {}", policy.getName(), e);
        }
    }

    private void reloadAuthorizationSystem() {
        policyRetrievalPoint.clearUrlPoliciesCache();
        policyRetrievalPoint.clearMethodPoliciesCache();
        authorizationManager.reload();
        if (policyReloadBroadcaster != null) {
            policyReloadBroadcaster.broadcastReload();
        }
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
                            .targetOrder(targetDto.getTargetOrder())
                            .sourceType(targetDto.getSourceType() != null ? targetDto.getSourceType() : "RESOURCE")
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
                        .targetOrder(targetDto.getTargetOrder())
                        .sourceType(targetDto.getSourceType() != null ? targetDto.getSourceType() : "RESOURCE")
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
