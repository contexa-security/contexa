package io.contexa.contexaiam.aiam.labs.data;

import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class PolicyGenerationCollectionService {

    private static final ExecutorService VIRTUAL_EXECUTOR = Executors.newVirtualThreadPerTaskExecutor();

    private final RoleService roleService;
    private final PermissionCatalogService permissionCatalogService;
    private final ConditionTemplateRepository conditionTemplateRepository;

    @Transactional(readOnly = true)
    public PolicyGenerationItem.AvailableItems collectData() {

        CompletableFuture<List<PolicyGenerationItem.RoleItem>> roles = CompletableFuture.supplyAsync(() -> {
            return roleService.getRolesWithoutExpression().stream()
                    .map(role -> new PolicyGenerationItem.RoleItem(role.getId(), role.getRoleName(), role.getRoleDesc()))
                    .toList();
        }, VIRTUAL_EXECUTOR);

        CompletableFuture<List<PolicyGenerationItem.PermissionItem>> permissions = CompletableFuture.supplyAsync(() -> {
            return permissionCatalogService.getAvailablePermissions().stream()
                    .map(permission -> new PolicyGenerationItem.PermissionItem(
                            permission.getId(),
                            permission.getName(),
                            permission.getDescription(),
                            permission.getTargetType(),
                            permission.getManagedResourceIdentifier(),
                            permission.getActionType()))
                    .toList();
        }, VIRTUAL_EXECUTOR);

        CompletableFuture<List<PolicyGenerationItem.ConditionItem>> conditions = CompletableFuture.supplyAsync(
                this::addContextAwareConditionsToModel, VIRTUAL_EXECUTOR
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
                            true
                    );
                })
                .toList();
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
