package io.contexa.contexaiam.aiam.labs.data;

import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.impl.RoleHierarchyService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;
import java.util.stream.Collectors;

@Slf4j
public class PolicyGenerationCollectionService {

    private final RoleService roleService;
    private final PermissionCatalogService permissionCatalogService;
    private final ConditionTemplateRepository conditionTemplateRepository;
    private final PolicyRepository policyRepository;
    private final RoleHierarchyService roleHierarchyService;
    private final Executor collectionExecutor;

    public PolicyGenerationCollectionService(
            RoleService roleService,
            PermissionCatalogService permissionCatalogService,
            ConditionTemplateRepository conditionTemplateRepository,
            PolicyRepository policyRepository,
            RoleHierarchyService roleHierarchyService) {
        this(
                roleService,
                permissionCatalogService,
                conditionTemplateRepository,
                policyRepository,
                roleHierarchyService,
                ForkJoinPool.commonPool());
    }

    public PolicyGenerationCollectionService(
            RoleService roleService,
            PermissionCatalogService permissionCatalogService,
            ConditionTemplateRepository conditionTemplateRepository,
            PolicyRepository policyRepository,
            RoleHierarchyService roleHierarchyService,
            Executor collectionExecutor) {
        this.roleService = roleService;
        this.permissionCatalogService = permissionCatalogService;
        this.conditionTemplateRepository = conditionTemplateRepository;
        this.policyRepository = policyRepository;
        this.roleHierarchyService = roleHierarchyService;
        this.collectionExecutor = collectionExecutor != null ? collectionExecutor : ForkJoinPool.commonPool();
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public PolicyGenerationItem.AvailableItems collectData() {

        CompletableFuture<List<PolicyGenerationItem.RoleItem>> roles = CompletableFuture.supplyAsync(() -> {
            return roleService.getRolesWithoutExpression().stream()
                    .map(role -> new PolicyGenerationItem.RoleItem(role.getId(), role.getRoleName(), role.getRoleDesc()))
                    .toList();
        }, collectionExecutor);

        CompletableFuture<List<PolicyGenerationItem.PermissionItem>> permissions = CompletableFuture.supplyAsync(() -> {
            return permissionCatalogService.getAvailablePermissions().stream()
                    .map(permission -> new PolicyGenerationItem.PermissionItem(
                            permission.getId(),
                            permission.getName(),
                            permission.getDescription(),
                            permission.getTargetType(),
                            permission.getLinkedResourceIdentifier(),
                            permission.getActionType()))
                    .toList();
        }, collectionExecutor);

        CompletableFuture<List<PolicyGenerationItem.ConditionItem>> conditions = CompletableFuture.supplyAsync(
                this::addContextAwareConditionsToModel, collectionExecutor
        );

        CompletableFuture.allOf(roles, permissions, conditions).join();

        return new PolicyGenerationItem.AvailableItems(roles.join(), permissions.join(), conditions.join());

    }

    private List<PolicyGenerationItem.ConditionItem> addContextAwareConditionsToModel() {

        List<ConditionTemplate> allConditions = conditionTemplateRepository.findAll();

        Map<ConditionTemplate.ConditionClassification, List<ConditionTemplate>> classifiedConditions =
                allConditions.stream()
                        .collect(Collectors.groupingBy(
                                cond -> cond.getClassification() != null ?
                                        cond.getClassification() : ConditionTemplate.ConditionClassification.UNIVERSAL));

        return allConditions.stream().map(cond -> {
                    String enhancedDescription = enhanceConditionDescription(cond);
                    return new PolicyGenerationItem.ConditionItem(
                            cond.getId(),
                            cond.getName(),
                            enhancedDescription,
                            null
                    );
                })
                .toList();
    }

    /**
     * Collect existing active policies summary for LLM context.
     * Helps AI avoid generating conflicting or duplicate policies.
     */
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public String collectExistingPoliciesSummary() {
        List<Policy> policies = policyRepository.findAllWithDetails();
        if (policies.isEmpty()) return "";

        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (Policy p : policies) {
            if (!p.getIsActive()) continue;
            if (count >= 50) {
                sb.append("... and ").append(policies.size() - 50).append(" more policies\n");
                break;
            }
            String targets = p.getTargets().stream()
                    .map(t -> t.getHttpMethod() + " " + t.getTargetIdentifier())
                    .collect(Collectors.joining(", "));
            String conditions = p.getRules().stream()
                    .flatMap(r -> r.getConditions().stream())
                    .map(PolicyCondition::getExpression)
                    .collect(Collectors.joining("; "));
            sb.append(String.format("- %s [%s]: %s | Condition: %s\n",
                    p.getName(), p.getEffect(), targets,
                    StringUtils.hasText(conditions) ? conditions : "none"));
            count++;
        }
        return sb.toString();
    }

    /**
     * Collect active role hierarchy string for LLM context.
     */
    public String collectRoleHierarchy() {
        try {
            String hierarchy = roleHierarchyService.getActiveRoleHierarchyString();
            return StringUtils.hasText(hierarchy) ? hierarchy : "";
        } catch (Exception e) {
            log.error("Failed to collect role hierarchy", e);
            return "";
        }
    }

    private String enhanceConditionDescription(ConditionTemplate cond) {
        StringBuilder desc = new StringBuilder();

        if (StringUtils.hasText(cond.getDescription())) {
            desc.append(cond.getDescription());
        }

        if (cond.getClassification() != null) {
            switch (cond.getClassification()) {
                case UNIVERSAL -> desc.append(" [UNIVERSAL - Ready to use]");
                case CONTEXT_DEPENDENT -> desc.append(" [CONTEXT_DEPENDENT - AI verification required]");
                case CUSTOM_COMPLEX -> desc.append(" [CUSTOM_COMPLEX - Expert review required]");
            }
        }

        if (cond.getComplexityScore() != null) {
            desc.append(" [Complexity: ").append(cond.getComplexityScore()).append("/10]");
        }

        if (Boolean.TRUE.equals(cond.getApprovalRequired())) {
            desc.append(" [Approval required]");
        }

        return desc.toString();
    }

}
