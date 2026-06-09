package io.contexa.contexaiam.admin.web.center.service;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.dto.BatchCreateRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyActionResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyBatchCreateResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyBatchItemResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyCleanupResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyMigrationResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyQuickCreateResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyRollbackRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterPolicyRequest;
import io.contexa.contexaiam.admin.web.center.dto.QuickPolicyRequest;
import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.domain.entity.policy.PolicyVersion;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.resource.util.ResourceTargetKey;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.service.BusinessPolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyEnrichmentService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyVersionService;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.MessageSource;
import org.springframework.context.event.EventListener;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Slf4j
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class PolicyCenterCommandService {

    private final ResourceRegistryService resourceRegistryService;
    private final PolicyService policyService;
    private final PolicyRepository policyRepository;
    private final RoleService roleService;
    private final BusinessPolicyService businessPolicyService;
    private final ManagedResourceRepository managedResourceRepository;
    private final PermissionRepository permissionRepository;
    private final PolicyValidationService policyValidationService;
    private final PolicyEnrichmentService policyEnrichmentService;
    private final PolicyVersionService policyVersionService;
    private final CustomDynamicAuthorizationManager authorizationManager;
    private final CentralAuditFacade centralAuditFacade;
    private final MessageSource messageSource;

    @Transactional(transactionManager = "contexaTransactionManager")
    public void refreshResources() {
        resourceRegistryService.refreshAndSynchronizeResources();

        List<Policy> policiesToUpdate = policyRepository.findByFriendlyDescriptionIsNull();
        if (!policiesToUpdate.isEmpty()) {
            for (Policy policy : policiesToUpdate) {
                policyEnrichmentService.enrichPolicyWithFriendlyDescription(policy);
                policyRepository.save(policy);
            }
        }

        synchronizeResourcePolicyStatus();
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public PolicyActionResponse createPolicyFromCenter(PolicyCenterPolicyRequest request) {
        try {
            policyService.createPolicy(request.toPolicyDto());
            return new PolicyActionResponse(true, msg("msg.policy.created"), null);
        } catch (DataIntegrityViolationException e) {
            log.error("Duplicate policy name", e);
            return new PolicyActionResponse(false, msg("msg.policy.name.duplicate"), null);
        } catch (Exception e) {
            log.error("Failed to create policy", e);
            return new PolicyActionResponse(false, msg("msg.policy.create.error", e.getMessage()), null);
        }
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public PolicyQuickCreateResponse quickCreatePolicy(QuickPolicyRequest request) {
        try {
            BusinessPolicyDto dto = new BusinessPolicyDto();
            dto.setPolicyName(request.getPolicyName());
            dto.setDescription(request.getDescription());
            dto.setEffect(request.getEffect());
            dto.setRoleIds(request.getRoleIds());
            dto.setPermissionIds(request.getPermissionIds());
            dto.setCrudPermissions(request.getCrudPermissions());
            dto.setConditions(Collections.emptyMap());
            dto.setSource(Policy.PolicySource.MANUAL);
            dto.setSpelId(request.getSpelId());

            if ("MANUAL".equals(request.getSourceType())) {
                dto.setSourceType("MANUAL");
                dto.setManualTargetType(request.getManualTargetType());
                dto.setManualTargetIdentifier(request.getManualTargetIdentifier());
                dto.setManualHttpMethod(request.getManualHttpMethod());
                dto.setManualTargetOrder(request.getManualTargetOrder());
            }

            List<String> duplicateAutoRoles = new ArrayList<>();
            if (request.getRoleIds() != null) {
                for (Long roleId : request.getRoleIds()) {
                    try {
                        Role role = roleService.getRole(roleId);
                        String autoPolicyName = "AUTO_POLICY_FOR_" + role.getRoleName();
                        if (policyRepository.findByName(autoPolicyName).isPresent()) {
                            duplicateAutoRoles.add(role.getRoleName());
                        }
                    } catch (Exception ignored) {
                    }
                }
            }

            Policy saved = businessPolicyService.createPolicyFromBusinessRule(dto);
            String warning = duplicateAutoRoles.isEmpty()
                    ? null
                    : msg("msg.policy.auto.duplicate.warning", String.join(", ", duplicateAutoRoles));
            return new PolicyQuickCreateResponse(true, saved.getId(), msg("msg.policy.created"), warning);
        } catch (DataIntegrityViolationException e) {
            log.error("Duplicate policy name", e);
            return new PolicyQuickCreateResponse(false, null, msg("msg.policy.name.duplicate"), null);
        } catch (Exception e) {
            log.error("Failed to create quick policy", e);
            return new PolicyQuickCreateResponse(false, null, msg("msg.policy.create.error", e.getMessage()), null);
        }
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public PolicyActionResponse resetPolicyStatus(List<Long> resourceIds) {
        if (resourceIds == null || resourceIds.isEmpty()) {
            return new PolicyActionResponse(false, msg("msg.policy.validation.target.required"), null);
        }
        int updated = 0;
        for (Long id : resourceIds) {
            try {
                AtomicBoolean changed = new AtomicBoolean(false);
                managedResourceRepository.findById(id).ifPresent(resource -> {
                    if (resource.getStatus() != ManagedResource.Status.PERMISSION_CREATED) {
                        return;
                    }
                    Permission perm = resource.getPermission();
                    if (perm != null) {
                        resource.setPermission(null);
                        managedResourceRepository.save(resource);
                        managedResourceRepository.flush();
                        permissionRepository.deleteById(perm.getId());
                        permissionRepository.flush();
                    }
                    resource.setStatus(ManagedResource.Status.NEEDS_DEFINITION);
                    managedResourceRepository.save(resource);
                    changed.set(true);
                });
                if (changed.get()) {
                    updated++;
                }
            } catch (Exception e) {
                log.error("Failed to reset resource status: {}", id, e);
            }
        }
        return new PolicyActionResponse(true, null, updated);
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public PolicyBatchCreateResponse batchCreatePolicies(BatchCreateRequest request) {
        try {
            if (request.getItems() == null || request.getItems().isEmpty()) {
                return new PolicyBatchCreateResponse(false, null, null, null,
                        msg("msg.policy.validation.target.required"));
            }
            Set<Long> roleIds = request.getRoleIds();
            List<Role> roles = new ArrayList<>();
            if (roleIds != null) {
                for (Long rid : roleIds) {
                    try {
                        roles.add(roleService.getRole(rid));
                    } catch (Exception ignored) {
                    }
                }
            }
            if (roles.isEmpty()) {
                return new PolicyBatchCreateResponse(false, null, null, null,
                        msg("msg.policy.batch.role.required"));
            }

            String roleCondition = roles.stream()
                    .map(r -> String.format("hasAuthority('%s')", r.getRoleName()))
                    .collect(Collectors.joining(" or "));
            String allRoleNames = roles.stream()
                    .map(Role::getRoleName)
                    .collect(Collectors.joining("_"));

            List<Policy> allExisting = policyRepository.findAllWithDetails();
            List<Policy> batchCreated = new ArrayList<>();
            List<PolicyBatchItemResponse> results = new ArrayList<>();

            for (BatchCreateRequest.BatchItem item : request.getItems()) {
                try {
                    if (item.getCrudPermissions() == null || item.getCrudPermissions().isEmpty()) {
                        results.add(new PolicyBatchItemResponse(
                                resourceIdentifierOrUnknown(item),
                                "SKIPPED",
                                msg("msg.policy.batch.no.crud"),
                                null,
                                null));
                        continue;
                    }

                    String crudCondition = new TreeSet<>(item.getCrudPermissions()).stream()
                            .map(c -> String.format("hasAuthority('%s')", c))
                            .collect(Collectors.joining(" or "));
                    String spelExpr = "(" + roleCondition + ") and (" + crudCondition + ")";

                    String crud = new TreeSet<>(item.getCrudPermissions()).stream()
                            .collect(Collectors.joining("_"));
                    String resPath = item.getResourceIdentifier() != null
                            ? item.getResourceIdentifier().replaceAll("[/{}]", "_")
                                    .replaceAll("^_+|_+$", "")
                                    .toUpperCase()
                            : "";
                    String rawName = request.getEffect().name() + "_" + allRoleNames + "_" + crud + "_" + resPath;
                    String policyName = rawName.replaceAll("_+", "_");
                    if (policyName.length() > 200) {
                        policyName = policyName.substring(0, 200);
                    }

                    Policy candidate = Policy.builder()
                            .name(policyName)
                            .description(item.getResourceIdentifier())
                            .effect(request.getEffect())
                            .priority(100)
                            .source(Policy.PolicySource.MANUAL)
                            .approvalStatus(Policy.ApprovalStatus.NOT_REQUIRED)
                            .isActive(true)
                            .build();

                    PolicyTarget target = PolicyTarget.builder()
                            .targetType(item.getResourceType() != null ? item.getResourceType() : "URL")
                            .targetIdentifier(item.getResourceIdentifier())
                            .httpMethod(item.getHttpMethod() != null ? item.getHttpMethod() : "ANY")
                            .sourceType("RESOURCE")
                            .build();
                    candidate.addTarget(target);

                    PolicyRule rule = PolicyRule.builder().build();
                    PolicyCondition condition = PolicyCondition.builder()
                            .expression(spelExpr)
                            .build();
                    rule.addCondition(condition);
                    candidate.addRule(rule);

                    List<Policy> checkAgainst = new ArrayList<>(allExisting);
                    checkAgainst.addAll(batchCreated);
                    var validationReport = policyValidationService.validate(candidate, checkAgainst);
                    if (!validationReport.canCreate()) {
                        results.add(new PolicyBatchItemResponse(
                                item.getResourceIdentifier(),
                                "SKIPPED",
                                validationReport.blockedReason() != null
                                        ? validationReport.blockedReason()
                                        : msg("msg.policy.validation.blocked.critical"),
                                null,
                                null));
                        continue;
                    }

                    policyEnrichmentService.enrichPolicyWithFriendlyDescription(candidate);
                    Policy saved = policyRepository.save(candidate);
                    policyVersionService.createVersion(saved, PolicyVersion.ChangeType.CREATED, null);

                    if (item.getPermissionId() != null) {
                        permissionRepository.findById(item.getPermissionId()).ifPresent(perm -> {
                            ManagedResource resource = perm.getManagedResource();
                            if (resource != null
                                    && resource.getStatus() == ManagedResource.Status.PERMISSION_CREATED) {
                                resource.setStatus(ManagedResource.Status.POLICY_CONNECTED);
                                managedResourceRepository.save(resource);
                            }
                        });
                    }

                    batchCreated.add(saved);
                    results.add(new PolicyBatchItemResponse(
                            item.getResourceIdentifier(),
                            "CREATED",
                            null,
                            saved.getId(),
                            saved.getName()));
                } catch (DataIntegrityViolationException e) {
                    results.add(new PolicyBatchItemResponse(
                            resourceIdentifierOrUnknown(item),
                            "ERROR",
                            msg("msg.policy.name.duplicate"),
                            null,
                            null));
                } catch (Exception e) {
                    log.error("Batch item failed: {}", item.getResourceIdentifier(), e);
                    results.add(new PolicyBatchItemResponse(
                            resourceIdentifierOrUnknown(item),
                            "ERROR",
                            msg("msg.policy.create.error", e.getMessage()),
                            null,
                            null));
                }
            }

            if (!batchCreated.isEmpty()) {
                authorizationManager.reload();
                auditBatchCreation(batchCreated.size(), request.getItems().size(), allRoleNames);
            }

            return new PolicyBatchCreateResponse(true, results, batchCreated.size(), request.getItems().size(), null);
        } catch (Exception e) {
            log.error("Batch policy creation failed", e);
            return new PolicyBatchCreateResponse(false, null, null, null,
                    msg("msg.policy.create.error", e.getMessage()));
        }
    }

    @EventListener(ApplicationReadyEvent.class)
    @Transactional(transactionManager = "contexaTransactionManager")
    public void autoMigratePolicyExpressions() {
        try {
            int migrated = executePolicyMigration();
            if (migrated > 0) {
                log.error("[migration] Auto-migrated {} policy expressions from URL_/METHOD_ to CRUD", migrated);
            }
        } catch (Exception e) {
            log.error("[migration] Auto-migration failed", e);
        }
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public PolicyMigrationResponse migratePolicyExpressionsToCrud() {
        try {
            int migrated = executePolicyMigration();
            return new PolicyMigrationResponse(true, migrated, null);
        } catch (Exception e) {
            log.error("Failed to migrate policy expressions", e);
            return new PolicyMigrationResponse(false, null, e.getMessage());
        }
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public PolicyCleanupResponse cleanupOldAutoCreatedPermissions() {
        try {
            List<Permission> oldPerms = permissionRepository.findAll().stream()
                    .filter(p -> p.isAutoCreated()
                            && p.getName() != null
                            && (p.getName().startsWith("URL_") || p.getName().startsWith("METHOD_")))
                    .toList();

            List<Long> deletedIds = new ArrayList<>();
            for (Permission perm : oldPerms) {
                if (perm.getManagedResource() != null) {
                    perm.setManagedResource(null);
                }
                deletedIds.add(perm.getId());
            }

            if (!deletedIds.isEmpty()) {
                permissionRepository.saveAll(oldPerms);
                permissionRepository.flush();
                permissionRepository.deleteAllByIds(deletedIds);
                permissionRepository.flush();
            }

            return new PolicyCleanupResponse(true, deletedIds.size(), null);
        } catch (Exception e) {
            log.error("Failed to cleanup old permissions", e);
            return new PolicyCleanupResponse(false, null, e.getMessage());
        }
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public PolicyActionResponse rollbackPolicy(
            Long policyId,
            int versionNumber,
            PolicyRollbackRequest request) {
        try {
            String reason = request != null ? request.reason() : null;
            policyService.rollbackPolicy(policyId, versionNumber, reason);
            return new PolicyActionResponse(true, msg("msg.policy.rollback.success"), null);
        } catch (Exception e) {
            log.error("Failed to rollback policy {} to version {}", policyId, versionNumber, e);
            return new PolicyActionResponse(false, e.getMessage(), null);
        }
    }

    private void synchronizeResourcePolicyStatus() {
        try {
            Set<String> allPolicyTargets = policyService.getAllPolicies().stream()
                    .flatMap(p -> p.getTargets().stream())
                    .map(ResourceTargetKey::ofPolicyTarget)
                    .collect(Collectors.toSet());

            managedResourceRepository.findByStatusInWithPermission(
                    List.of(ManagedResource.Status.POLICY_CONNECTED)
            ).forEach(resource -> {
                String key = ResourceTargetKey.ofResource(resource);
                if (!allPolicyTargets.contains(key)) {
                    resource.setStatus(ManagedResource.Status.PERMISSION_CREATED);
                    managedResourceRepository.save(resource);
                }
            });

            managedResourceRepository.findByStatusInWithPermission(
                    List.of(ManagedResource.Status.PERMISSION_CREATED)
            ).forEach(resource -> {
                String key = ResourceTargetKey.ofResource(resource);
                if (allPolicyTargets.contains(key)) {
                    resource.setStatus(ManagedResource.Status.POLICY_CONNECTED);
                    managedResourceRepository.save(resource);
                }
            });
        } catch (Exception e) {
            log.error("Failed to synchronize resource policy status", e);
        }
    }

    private int executePolicyMigration() {
        int migrated = 0;
        List<Policy> allPolicies = policyRepository.findAllWithDetails();
        for (Policy policy : allPolicies) {
            boolean changed = false;
            for (PolicyRule rule : policy.getRules()) {
                for (PolicyCondition condition : rule.getConditions()) {
                    String expr = condition.getExpression();
                    if (expr == null) {
                        continue;
                    }
                    String newExpr = migrateExpressionToCrud(expr);
                    if (!expr.equals(newExpr)) {
                        condition.setExpression(newExpr);
                        changed = true;
                    }
                }
            }
            if (changed) {
                policyEnrichmentService.enrichPolicyWithFriendlyDescription(policy);
                policyRepository.save(policy);
                migrated++;
            }
        }
        return migrated;
    }

    private String migrateExpressionToCrud(String expression) {
        Pattern pattern = Pattern.compile("hasAuthority\\('(URL_|METHOD_)([^']*)'\\)");
        Matcher matcher = pattern.matcher(expression);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            String permName = matcher.group(1) + matcher.group(2);
            String crud = resolvePermissionToCrud(permName);
            matcher.appendReplacement(sb, "hasAuthority('" + crud + "')");
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    private String resolvePermissionToCrud(String permissionName) {
        return permissionRepository.findByName(permissionName)
                .map(perm -> {
                    ManagedResource resource = perm.getManagedResource();
                    if (resource != null && resource.getHttpMethod() != null) {
                        return switch (resource.getHttpMethod().name()) {
                            case "GET" -> "READ";
                            case "POST" -> "WRITE";
                            case "PUT", "PATCH" -> "UPDATE";
                            case "DELETE" -> "DELETE";
                            default -> "READ";
                        };
                    }
                    String upper = permissionName.toUpperCase();
                    if (upper.contains("DELETE") || upper.contains("REMOVE")) {
                        return "DELETE";
                    }
                    if (upper.contains("CREATE") || upper.contains("SAVE")
                            || upper.contains("ADD") || upper.contains("POST")) {
                        return "WRITE";
                    }
                    if (upper.contains("UPDATE") || upper.contains("EDIT")
                            || upper.contains("MODIFY") || upper.contains("PUT")) {
                        return "UPDATE";
                    }
                    return "READ";
                })
                .orElse("READ");
    }

    private void auditBatchCreation(int created, int total, String allRoleNames) {
        try {
            String principal = "SYSTEM";
            var auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getName() != null) {
                principal = auth.getName();
            }
            centralAuditFacade.recordAsync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.POLICY_CREATED)
                    .principalName(principal)
                    .resourceIdentifier("batch-create")
                    .eventSource("IAM")
                    .action("BATCH_POLICY_CREATED")
                    .decision("SUCCESS")
                    .outcome("SUCCESS")
                    .details(Map.of(
                            "created", created,
                            "total", total,
                            "roles", allRoleNames,
                            "source", "MANUAL"))
                    .build());
        } catch (Exception ae) {
            log.error("Failed to audit batch policy creation", ae);
        }
    }

    private String resourceIdentifierOrUnknown(BatchCreateRequest.BatchItem item) {
        return item.getResourceIdentifier() != null ? item.getResourceIdentifier() : "unknown";
    }

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }
}
