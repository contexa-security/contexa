/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.security.xacml.pap.service;

import java.util.Locale;
import java.util.Optional;
import io.contexa.contexaiam.common.ConsoleInput;
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
import io.contexa.contexaiam.security.xacml.pdp.evaluation.PolicyExpressionValidator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.SpelLiteral;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.UnsafePolicyExpressionException;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexacore.infra.redis.PolicyReloadBroadcaster;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager")
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
    private final MessageSource messageSource;
    private final AIPolicyValidator aiPolicyValidator;

    @Setter
    private PolicyReloadBroadcaster policyReloadBroadcaster;

    private static final Pattern AUTHORITY_PATTERN = Pattern.compile("hasAuthority\\(" + SpelLiteral.PATTERN + "\\)");

    /** The columns of a policy's name, description, target and rule description (ctxa_policy, ctxa_policy_target). */
    public static final int TEXT_MAX = 255;
    /** ctxa_policy_condition.condition_expression */
    public static final int CONDITION_MAX = 2048;
    /** ctxa_policy_version.change_reason */
    public static final int CHANGE_REASON_MAX = 1024;

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<Policy> getAllPolicies() {
        return policyRepository.findAllWithDetails();
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Page<Policy> searchPolicies(String keyword, Pageable pageable) {
        String pattern = (keyword != null && !keyword.isBlank()) ? "%" + keyword.toLowerCase(Locale.ROOT) + "%" : null;
        return policyRepository.searchByKeyword(pattern, pageable);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Page<Policy> searchPolicies(String keyword, Policy.ApprovalStatus approvalStatus, Boolean activeFilter, Pageable pageable) {
        String pattern = (keyword != null && !keyword.isBlank()) ? "%" + keyword.toLowerCase(Locale.ROOT) + "%" : null;
        return policyRepository.searchByFilters(pattern, approvalStatus, activeFilter, pageable);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Policy findById(Long id) {
        return policyRepository.findByIdWithDetails(id)
                .orElseThrow(() -> new IllegalArgumentException(i18n("msg.policy.not.found", id)));
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Optional<Policy> findPolicy(Long id) {
        return id == null ? Optional.empty() : policyRepository.findByIdWithDetails(id);
    }

    @Override
    public Policy createPolicy(PolicyDto policyDto) {
        validateInput(policyDto);
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
        checkFormValues(policyDto);
        validateConditionExpressions(policyDto);
        refuseSeedChange(policyDto.getId(), policyDto);
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
                        permissionNames.add(SpelLiteral.unquote(matcher.group(1)));
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
        String expression = SpelLiteral.hasAuthority(permission.getName());

        PolicyDto policyDto = PolicyDto.builder()
                .name(policyName)
                // D31: the permission name, not its friendly name, which may be in another language than the sentence.
                .description(String.format("Auto-generated policy for permission '%s'", permission.getName()))
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
        Policy policy = policyRepository.findByIdWithDetails(id)
                .orElseThrow(() -> new IllegalArgumentException(i18n("msg.policy.not.found", id)));
        refuseSeedRemoval(policy);

        // Cleanup: revert resources and delete auto-created permissions
        cleanupResourcesForPolicy(policy, id);

        // Audit before delete
        auditPolicyChange(AuditEventCategory.POLICY_DELETED, policy);

        // Delete policy versions
        policyVersionService.deleteByPolicyId(id);

        // Delete policy (cascade: targets, rules, conditions)
        policyRepository.deleteById(id);

        eventBus.publish(new PolicyChangedEvent(id, new HashSet<>()));
        reloadAuthorizationSystem();
    }

    private void cleanupResourcesForPolicy(Policy policy, Long policyId) {
        List<Permission> permsToDelete = new ArrayList<>();
        List<ManagedResource> resourcesToReset = new ArrayList<>();

        // Collect from policy targets
        policy.getTargets().stream()
                .map(PolicyTarget::getTargetIdentifier)
                .distinct()
                .forEach(identifier -> managedResourceRepository.findByResourceIdentifier(identifier).ifPresent(resource -> {
                    long otherCount = policyRepository.countOtherPoliciesForTarget(
                            resource.getResourceType().name(), resource.getResourceIdentifier(), policyId);
                    if (otherCount == 0) {
                        Permission perm = resource.getPermission();
                        if (perm != null && perm.isAutoCreated()) {
                            permsToDelete.add(perm);
                        }
                        resourcesToReset.add(resource);
                    }
                }));

        // Collect from condition expressions
        Set<String> permNames = new HashSet<>();
        policy.getRules().stream()
                .flatMap(rule -> rule.getConditions().stream())
                .map(PolicyCondition::getExpression)
                .forEach(spel -> {
                    Matcher matcher = AUTHORITY_PATTERN.matcher(spel);
                    while (matcher.find()) permNames.add(SpelLiteral.unquote(matcher.group(1)));
                });
        if (!permNames.isEmpty()) {
            permissionRepository.findAllByNameIn(permNames).forEach(perm -> {
                ManagedResource resource = perm.getManagedResource();
                if (resource != null && resource.getStatus() == ManagedResource.Status.POLICY_CONNECTED
                        && !resourcesToReset.contains(resource)) {
                    long otherCount = policyRepository.countOtherPoliciesForTarget(
                            resource.getResourceType().name(), resource.getResourceIdentifier(), policyId);
                    if (otherCount == 0) {
                        if (perm.isAutoCreated() && !permsToDelete.contains(perm)) {
                            permsToDelete.add(perm);
                        }
                        resourcesToReset.add(resource);
                    }
                }
            });
        }

        // Step 1: Unlink permissions from resources
        if (!permsToDelete.isEmpty()) {
            List<Long> permIds = permsToDelete.stream().map(Permission::getId).toList();
            for (Permission perm : permsToDelete) {
                perm.setManagedResource(null);
            }
            permissionRepository.saveAll(permsToDelete);
            permissionRepository.flush();
            // Step 2: JPQL delete (bypasses Hibernate cascade re-insert)
            permissionRepository.deleteAllByIds(permIds);
            permissionRepository.flush();
        }

        // Step 3: Reset resource status
        for (ManagedResource resource : resourcesToReset) {
            resource.setPermission(null);
            resource.setStatus(ManagedResource.Status.NEEDS_DEFINITION);
        }
        if (!resourcesToReset.isEmpty()) {
            managedResourceRepository.saveAll(resourcesToReset);
        }
    }

    @Override
    public void approvePolicy(Long id, String approver) {
        Policy policy = findById(id);
        if (policy.getApprovalStatus() == Policy.ApprovalStatus.APPROVED) {
            throw new IllegalStateException(i18n("msg.policy.already.approved"));
        }
        validateConditionExpressions(policy);

        if (policy.isAIGenerated()) {
            AIPolicyValidationReport validationReport = aiPolicyValidator.validate(policy);
            if (!validationReport.canApprove()) {
                throw new IllegalStateException(
                        i18n("msg.policy.ai.validation.failed", validationReport.blockedReason()));
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
        refuseSeedRemoval(policy);
        if (policy.getApprovalStatus() == Policy.ApprovalStatus.REJECTED) {
            throw new IllegalStateException(i18n("msg.policy.already.rejected"));
        }
        policy.reject(rejector);
        policyRepository.save(policy);
        auditPolicyChange(AuditEventCategory.POLICY_UPDATED, policy);
        reloadAuthorizationSystem();
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<PolicyConflictDto> detectConflicts(PolicyDto policyDto) {
        Policy policy = convertDtoToEntity(policyDto);
        if (policyDto.getId() != null) {
            policy.setId(policyDto.getId());
        }
        return policyConflictAnalyzer.analyze(policy);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<PolicyVersion> getVersions(Long policyId) {
        return policyVersionService.getVersions(policyId);
    }

    @Override
    public Policy rollbackPolicy(Long policyId, int versionNumber, String reason) {
        PolicyVersion version = policyVersionService.getVersion(policyId, versionNumber)
                .orElseThrow(() -> new IllegalArgumentException(
                        i18n("msg.policy.version.not.found", versionNumber, policyId)));

        PolicyDto snapshotDto = policyVersionService.deserializeSnapshot(version)
                .orElseThrow(() -> new IllegalStateException(
                        i18n("msg.policy.version.deserialize.failed", versionNumber)));
        validateConditionExpressions(snapshotDto);
        refuseSeedChange(policyId, snapshotDto);

        String rollbackReason = i18n("msg.policy.version.rollback.reason",
                versionNumber, reason != null ? ": " + reason : "");
        if (reason != null && rollbackReason.length() > CHANGE_REASON_MAX) {
            // D67: the reason typed, refused by the room the version's text leaves it in the column.
            ConsoleInput.unchanged(messageSource, "policy.field.change.reason", reason,
                    CHANGE_REASON_MAX - (rollbackReason.length() - reason.length()));
        }

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
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public PolicyValidationReport validateBeforeCreate(PolicyDto policyDto) {
        Policy policy = convertDtoToEntity(policyDto);
        if (policyDto.getId() != null) {
            policy.setId(policyDto.getId());
        }
        return policyValidationService.validate(policy);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public PolicyImpactReport analyzeImpact(PolicyDto policyDto) {
        Policy policy = convertDtoToEntity(policyDto);
        if (policyDto.getId() != null) {
            policy.setId(policyDto.getId());
        }
        return policyImpactAnalyzer.analyze(policy);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public AIPolicyValidationReport validateAIPolicy(Long policyId) {
        Policy policy = findById(policyId);
        return aiPolicyValidator.validate(policy);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
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

    private void validateInput(PolicyDto dto) {
        if (dto.getName() == null || dto.getName().isBlank()) {
            throw new IllegalArgumentException(i18n("msg.policy.validation.name.required"));
        }
        if (dto.getEffect() == null) {
            throw new IllegalArgumentException(i18n("msg.policy.validation.effect.required"));
        }
        if (dto.getTargets() == null || dto.getTargets().isEmpty()) {
            throw new IllegalArgumentException(i18n("msg.policy.validation.target.required"));
        }
        checkFormValues(dto);
        validateConditionExpressions(dto);
    }

    /**
     * D67: the values of a policy form against the columns they are kept in, refused with the field and its limit
     * instead of the database's constraint. Names, descriptions and targets are kept without the blanks around them.
     */
    private void checkFormValues(PolicyDto dto) {
        dto.setName(ConsoleInput.required(messageSource, "policy.field.name", dto.getName(), TEXT_MAX));
        dto.setDescription(ConsoleInput.optional(messageSource, "policy.field.description", dto.getDescription(),
                TEXT_MAX));
        dto.setChangeReason(ConsoleInput.optional(messageSource, "policy.field.change.reason", dto.getChangeReason(),
                CHANGE_REASON_MAX));
        if (dto.getTargets() != null) {
            for (TargetDto target : dto.getTargets()) {
                if (target != null) {
                    target.setTargetIdentifier(ConsoleInput.required(messageSource, "policy.field.target.identifier",
                            target.getTargetIdentifier(), TEXT_MAX));
                }
            }
        }
        if (dto.getRules() == null) {
            return;
        }
        for (RuleDto rule : dto.getRules()) {
            if (rule == null) {
                continue;
            }
            rule.setDescription(ConsoleInput.optional(messageSource, "policy.field.rule.description",
                    rule.getDescription(), TEXT_MAX));
            if (rule.getConditions() != null) {
                for (ConditionDto condition : rule.getConditions()) {
                    if (condition != null) {
                        ConsoleInput.unchanged(messageSource, "policy.field.condition", condition.getExpression(),
                                CONDITION_MAX);
                    }
                }
            }
        }
    }

    private void validateConditionExpressions(PolicyDto dto) {
        if (dto.getRules() == null) {
            return;
        }
        for (RuleDto rule : dto.getRules()) {
            if (rule == null || rule.getConditions() == null) {
                continue;
            }
            for (ConditionDto condition : rule.getConditions()) {
                if (condition != null) {
                    validateConditionExpression(condition.getExpression());
                }
            }
        }
    }

    private void validateConditionExpressions(Policy policy) {
        policy.getRules().stream()
                .flatMap(rule -> rule.getConditions().stream())
                .forEach(condition -> validateConditionExpression(condition.getExpression()));
    }

    private void validateConditionExpression(String expression) {
        try {
            PolicyExpressionValidator.validate(expression);
        } catch (UnsafePolicyExpressionException e) {
            throw new IllegalArgumentException(i18n(e.getMessageKey(), e.getReason()), e);
        }
    }

    /** D46: the seed policy that opens the sign-in page and the one that keeps the admin area stay in force. */
    private void refuseSeedRemoval(Policy policy) {
        SeedPolicyGuard.refuseRemoval(policy.getId()).ifPresent(key -> {
            log.warn("Removal of seed policy refused. policyId={}, name={}", policy.getId(), policy.getName());
            throw new IllegalStateException(i18n(key, policy.getId(), policy.getName()));
        });
    }

    /** D46: an edit that would widen what a seed policy lets through is refused. */
    private void refuseSeedChange(Long policyId, PolicyDto dto) {
        SeedPolicyGuard.refuseChange(policyId, dto).ifPresent(key -> {
            log.warn("Widening edit of seed policy refused. policyId={}", policyId);
            throw new IllegalStateException(i18n(key, policyId));
        });
    }

    private void validateConflicts(Policy policy) {
        List<PolicyConflictDto> conflicts = policyConflictAnalyzer.analyze(policy);
        List<PolicyConflictDto> blockingConflicts = conflicts.stream()
                .filter(c -> c.severity() == PolicyConflictDto.Severity.CRITICAL
                        || c.severity() == PolicyConflictDto.Severity.HIGH)
                .toList();
        if (!blockingConflicts.isEmpty()) {
            String details = blockingConflicts.stream()
                    .map(c -> String.format("[%s/%s] %s", c.severity(), c.existingPolicyName(), c.conflictDescription()))
                    .collect(Collectors.joining("; "));
            throw new PolicyConflictException(
                    i18n("msg.policy.validation.conflicts.detected", details), conflicts);
        }
    }

    private String i18n(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
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

    /** Reloads the policies of this node and of the others once the change has committed (D61). */
    private void reloadAuthorizationSystem() {
        PolicyReloadAfterCommit.schedule(() -> {
            policyRetrievalPoint.clearUrlPoliciesCache();
            policyRetrievalPoint.clearMethodPoliciesCache();
            authorizationManager.reload();
            if (policyReloadBroadcaster != null) {
                policyReloadBroadcaster.broadcastReload();
            }
        });
    }

    private Policy convertDtoToEntity(PolicyDto dto) {
        // The rule of the business rule path (CF-03): an AI-written policy waits for an administrator's approval, any
        // other policy (manual, imported, kept in sync with a permission) takes effect without one. The source given
        // is kept; a policy that names none is a manual one.
        Policy.PolicySource source = dto.getSource() != null ? dto.getSource() : Policy.PolicySource.MANUAL;
        Policy policy = Policy.builder()
                .name(dto.getName())
                .description(dto.getDescription())
                .effect(dto.getEffect())
                .priority(dto.getPriority())
                .source(source)
                .approvalStatus(source == Policy.PolicySource.AI_GENERATED || source == Policy.PolicySource.AI_EVOLVED
                        ? Policy.ApprovalStatus.PENDING : Policy.ApprovalStatus.NOT_REQUIRED)
                .isActive(true)
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
