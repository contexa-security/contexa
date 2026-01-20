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

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class PolicyGenerationCollectionService {

    private final RoleService roleService;
    private final PermissionCatalogService permissionCatalogService;
    private final ConditionTemplateRepository conditionTemplateRepository;
    private static final Pattern SPEL_VARIABLE_PATTERN = Pattern.compile("#(\\w+)");
    private static final Set<String> GLOBAL_CONTEXT_VARIABLES = Set.of("#authentication", "#request", "#ai");

    
    @Transactional(readOnly = true)
    public PolicyGenerationItem.AvailableItems collectData() {

        CompletableFuture<List<PolicyGenerationItem.RoleItem>> roles = CompletableFuture.supplyAsync(() -> {
            return roleService.getRolesWithoutExpression().stream()
                    .map(role -> new PolicyGenerationItem.RoleItem(role.getId(), role.getRoleName(), role.getRoleDesc()))
                    .toList();
        }, Executors.newVirtualThreadPerTaskExecutor());

        CompletableFuture<List<PolicyGenerationItem.PermissionItem>> permissions = CompletableFuture.supplyAsync(() -> {
            return permissionCatalogService.getAvailablePermissions().stream()
                    .map(permission -> new PolicyGenerationItem.PermissionItem(permission.getId(),permission.getName(),permission.getDescription()))
                    .toList();
        }, Executors.newVirtualThreadPerTaskExecutor());

        CompletableFuture<List<PolicyGenerationItem.ConditionItem>> conditions = CompletableFuture.supplyAsync(
                this::addContextAwareConditionsToModel, Executors.newVirtualThreadPerTaskExecutor()
        );

        
        CompletableFuture.allOf(roles, permissions, conditions).join();
        permissions.join();

        return new PolicyGenerationItem.AvailableItems(roles.join(), permissions.join(), conditions.join());

    }

    private List<PolicyGenerationItem.ConditionItem> addContextAwareConditionsToModel() {

        List<ConditionTemplate> allConditions = conditionTemplateRepository.findAll();

        
        Map<ConditionTemplate.ConditionClassification, List<ConditionTemplate>> classifiedConditions =
                allConditions.stream()
                        .collect(Collectors.groupingBy(
                                cond -> cond.getClassification() != null ?
                                        cond.getClassification() : ConditionTemplate.ConditionClassification.UNIVERSAL));

        Map<ConditionTemplate.RiskLevel, List<ConditionTemplate>> riskGrouped =
                allConditions.stream()
                        .collect(Collectors.groupingBy(
                                cond -> cond.getRiskLevel() != null ?
                                        cond.getRiskLevel() : ConditionTemplate.RiskLevel.LOW));

        log.info("조건 템플릿 로드 (분류별): 범용 {} 개, 컨텍스트의존 {} 개, 복잡 {} 개",
                classifiedConditions.getOrDefault(ConditionTemplate.ConditionClassification.UNIVERSAL, Collections.emptyList()).size(),
                classifiedConditions.getOrDefault(ConditionTemplate.ConditionClassification.CONTEXT_DEPENDENT, Collections.emptyList()).size(),
                classifiedConditions.getOrDefault(ConditionTemplate.ConditionClassification.CUSTOM_COMPLEX, Collections.emptyList()).size());

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
                case UNIVERSAL -> desc.append(" 🟢 (즉시 사용 가능)");
                case CONTEXT_DEPENDENT -> desc.append(" 🟡 (AI 검증 필요)");
                case CUSTOM_COMPLEX -> desc.append(" 🔴 (전문가 검토)");
            }
        }

        
        if (cond.getComplexityScore() != null) {
            desc.append(" [복잡도: ").append(cond.getComplexityScore()).append("/10]");
        }

        
        if (Boolean.TRUE.equals(cond.getApprovalRequired())) {
            desc.append(" 승인필요");
        }

        return desc.toString();
    }

    
    private int getClassificationOrder(ConditionTemplate.ConditionClassification classification) {
        if (classification == null) return 2;
        return switch (classification) {
            case UNIVERSAL -> 1;
            case CONTEXT_DEPENDENT -> 2;
            case CUSTOM_COMPLEX -> 3;
        };
    }

    private Set<String> extractVariablesFromSpel(String spelTemplate) {
        Set<String> variables = new HashSet<>();
        if (spelTemplate == null) return variables;
        Matcher matcher = SPEL_VARIABLE_PATTERN.matcher(spelTemplate);
        while (matcher.find()) {
            variables.add(matcher.group()); 
        }
        return variables;
    }
}