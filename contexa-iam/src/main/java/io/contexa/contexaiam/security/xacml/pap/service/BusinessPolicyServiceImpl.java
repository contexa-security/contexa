package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Slf4j
@Transactional
public class BusinessPolicyServiceImpl implements BusinessPolicyService {

    private final PolicyRepository policyRepository;
    private final RoleService roleService;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final ConditionTemplateRepository conditionTemplateRepository;
    private final PolicyEnrichmentService policyEnrichmentService;
    private final CustomDynamicAuthorizationManager authorizationManager;

    public BusinessPolicyServiceImpl(PolicyRepository policyRepository,
                                     @Lazy RoleService roleService, 
                                     RoleRepository roleRepository,
                                     PermissionRepository permissionRepository,
                                     ConditionTemplateRepository conditionTemplateRepository,
                                     PolicyEnrichmentService policyEnrichmentService,
                                     CustomDynamicAuthorizationManager authorizationManager) {
        this.policyRepository = policyRepository;
        this.roleService = roleService;
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.conditionTemplateRepository = conditionTemplateRepository;
        this.policyEnrichmentService = policyEnrichmentService;
        this.authorizationManager = authorizationManager;
    }

    @Override
    public Policy createPolicyFromBusinessRule(BusinessPolicyDto dto) {
        if (CollectionUtils.isEmpty(dto.getRoleIds()) || CollectionUtils.isEmpty(dto.getPermissionIds())) {
            throw new IllegalArgumentException("At least one role and one permission must be selected to create a policy.");
        }

        Policy policy = new Policy();
        translateAndApplyDtoToPolicy(policy, dto);

        policyEnrichmentService.enrichPolicyWithFriendlyDescription(policy);

        Policy savedPolicy = policyRepository.save(policy);
        updateResourceStatusForPermissions(dto.getPermissionIds());
        authorizationManager.reload();

                return savedPolicy;
    }

    @Override
    public Policy updatePolicyFromBusinessRule(Long policyId, BusinessPolicyDto dto) {
        Policy existingPolicy = policyRepository.findByIdWithDetails(policyId)
                .orElseThrow(() -> new IllegalArgumentException("Policy not found with id: " + policyId));

        updateRolePermissionMappings(dto.getRoleIds(), dto.getPermissionIds());

        translateAndApplyDtoToPolicy(existingPolicy, dto);
        policyEnrichmentService.enrichPolicyWithFriendlyDescription(existingPolicy);

        Policy updatedPolicy = policyRepository.save(existingPolicy);
        authorizationManager.reload();

                return updatedPolicy;
    }

    private void translateAndApplyDtoToPolicy(Policy policy, BusinessPolicyDto dto) {
        policy.setName(dto.getPolicyName());
        policy.setDescription(dto.getDescription());
        policy.setEffect(dto.getEffect());
        policy.setPriority(100);

        policy.getTargets().clear();
        policy.getRules().clear();

        Set<Permission> permissions = new HashSet<>(permissionRepository.findAllById(dto.getPermissionIds()));
        Set<PolicyTarget> targets = permissions.stream()
                .map(Permission::getManagedResource)
                .filter(Objects::nonNull)
                .map(mr -> PolicyTarget.builder()
                        .targetType(mr.getResourceType().name())
                        .targetIdentifier(mr.getResourceIdentifier())
                        .httpMethod(mr.getHttpMethod() != null ? mr.getHttpMethod().name() : "ANY")
                        .build())
                .collect(Collectors.toSet());
        
        targets.forEach(policy::addTarget);

        String spelCondition = buildSpelCondition(dto);
        if (StringUtils.hasText(spelCondition)) {
            PolicyRule rule = PolicyRule.builder()
                    .description("Dynamic rule created/modified by intelligent builder")
                    .build();

            PolicyCondition condition = PolicyCondition.builder()
                    .expression(spelCondition)
                    .build();

            rule.addCondition(condition);
            policy.addRule(rule);
        }
    }

    private void updateRolePermissionMappings(Set<Long> roleIds, Set<Long> permissionIdsToAdd) {
        if (CollectionUtils.isEmpty(roleIds)) return;

        for (Long roleId : roleIds) {
            Role role = roleService.getRole(roleId);
            List<Long> currentPermissionIds = role.getRolePermissions().stream()
                    .map(rp -> rp.getPermission().getId())
                    .toList();

            Set<Long> updatedPermissionIdSet = new HashSet<>(currentPermissionIds);
            updatedPermissionIdSet.addAll(permissionIdsToAdd);

            roleService.updateRole(role, new ArrayList<>(updatedPermissionIdSet));
        }
    }

    private String buildSpelCondition(BusinessPolicyDto dto) {
        List<String> allConditions = new ArrayList<>();

        List<Role> roles = roleRepository.findAllById(dto.getRoleIds());
        String roleCondition = roles.stream()
                .map(Role::getRoleName)
                .map(name -> String.format("hasAuthority('%s')", name))
                .collect(Collectors.joining(" or "));
        if (StringUtils.hasText(roleCondition)) {
            allConditions.add("(" + roleCondition + ")");
        }

        List<Permission> permissions = new ArrayList<>(permissionRepository.findAllById(dto.getPermissionIds()));
        String permissionCondition = permissions.stream()
                .map(Permission::getName)
                .map(name -> String.format("hasAuthority('%s')", name))
                .collect(Collectors.joining(" or "));
        if (StringUtils.hasText(permissionCondition)) {
            allConditions.add("(" + permissionCondition + ")");
        }

        if (dto.isAiActionEnabled() && !CollectionUtils.isEmpty(dto.getAllowedActions())) {
            List<String> actions = dto.getAllowedActions();
            if (actions.size() == 1) {
                String action = actions.getFirst();
                String expr = switch (action.toUpperCase()) {
                    case "ALLOW" -> "#ai.isAllowed()";
                    case "BLOCK" -> "#ai.isBlocked()";
                    case "CHALLENGE" -> "#ai.needsChallenge()";
                    case "ESCALATE" -> "#ai.needsEscalation()";
                    default -> "#ai.hasAction('" + action + "')";
                };
                allConditions.add(expr);
            } else {
                String actionList = actions.stream()
                        .map(a -> "'" + a.toUpperCase() + "'")
                        .collect(Collectors.joining(","));
                allConditions.add("#ai.hasActionIn(" + actionList + ")");
            }
        }
        if (StringUtils.hasText(dto.getCustomConditionSpel())) {
            validateSpelSafety(dto.getCustomConditionSpel());
            allConditions.add("(" + dto.getCustomConditionSpel() + ")");
        }
        if (!CollectionUtils.isEmpty(dto.getConditions())) {
            dto.getConditions().forEach((templateId, params) -> {
                ConditionTemplate template = conditionTemplateRepository.findById(templateId)
                        .orElseThrow(() -> new IllegalArgumentException("Condition template not found: " + templateId));
                Object[] quotedParams = params.stream().map(p -> "'" + p + "'").toArray();
                allConditions.add(String.format(template.getSpelTemplate(), quotedParams));
            });
        }

        return String.join(" and ", allConditions);
    }

    @Override
    public BusinessPolicyDto getBusinessRuleForPolicy(Long policyId) {
        Policy policy = policyRepository.findByIdWithDetails(policyId)
                .orElseThrow(() -> new IllegalArgumentException("Policy not found with id: " + policyId));

        return translatePolicyToBusinessRule(policy);
    }

    @Override
    public BusinessPolicyDto translatePolicyToBusinessRule(Long policyId) {
        return getBusinessRuleForPolicy(policyId);
    }

    private BusinessPolicyDto translatePolicyToBusinessRule(Policy policy) {
        BusinessPolicyDto dto = new BusinessPolicyDto();

        dto.setPolicyName(policy.getName());
        dto.setDescription(policy.getDescription());
        dto.setEffect(policy.getEffect());

        Set<Long> permissionIds = extractPermissionIds(policy);
        dto.setPermissionIds(permissionIds);

        Set<Long> roleIds = extractRoleIds(policy);
        dto.setRoleIds(roleIds);

        analyzeConditions(policy, dto);

        return dto;
    }

    private Set<Long> extractPermissionIds(Policy policy) {
        Set<Long> permissionIds = new HashSet<>();

        for (PolicyTarget target : policy.getTargets()) {
            
            try {
                ManagedResource.ResourceType resourceType =
                        ManagedResource.ResourceType.valueOf(target.getTargetType());

                List<Permission> permissions = permissionRepository.findByResourceTypeAndIdentifier(
                    resourceType,
                    target.getTargetIdentifier()
                );

                permissions.stream()
                    .map(Permission::getId)
                    .forEach(permissionIds::add);

            } catch (IllegalArgumentException e) {
                log.error("Unknown resource type: {} (target: {})", target.getTargetType(), target.getTargetIdentifier());
            }
        }

        return permissionIds;
    }

    private Set<Long> extractRoleIds(Policy policy) {
        Set<Long> roleIds = new HashSet<>();

        for (PolicyRule rule : policy.getRules()) {
            for (PolicyCondition condition : rule.getConditions()) {
                String expression = condition.getExpression();
                if (StringUtils.hasText(expression)) {
                    
                    Set<String> roleNames = extractRoleNamesFromSpel(expression);

                    for (String roleName : roleNames) {
                        roleRepository.findByRoleName(roleName)
                            .ifPresent(role -> roleIds.add(role.getId()));
                    }
                }
            }
        }

        return roleIds;
    }

    private Set<String> extractRoleNamesFromSpel(String spelExpression) {
        Set<String> roleNames = new HashSet<>();

        Pattern pattern = Pattern.compile("hasAuthority\\('([^']+)'\\)");
        Matcher matcher = pattern.matcher(spelExpression);

        while (matcher.find()) {
            String name = matcher.group(1);
            if (!isPermissionName(name)) {
                roleNames.add(name);
            }
        }

        return roleNames;
    }

    private boolean isPermissionName(String name) {
        return name.startsWith("URL_") || name.startsWith("METHOD_");
    }

    private void analyzeConditions(Policy policy, BusinessPolicyDto dto) {
        for (PolicyRule rule : policy.getRules()) {
            for (PolicyCondition condition : rule.getConditions()) {
                String expression = condition.getExpression();
                if (StringUtils.hasText(expression)) {
                    
                    analyzeAiCondition(expression, dto);

                    extractCustomSpelCondition(expression, dto);
                }
            }
        }
    }

    private void analyzeAiCondition(String expression, BusinessPolicyDto dto) {
        if (expression.contains("#ai.isAllowed()")) {
            dto.setAiActionEnabled(true);
            dto.setAllowedActions(List.of(ZeroTrustAction.ALLOW.name()));
            return;
        }
        if (expression.contains("#ai.isBlocked()")) {
            dto.setAiActionEnabled(true);
            dto.setAllowedActions(List.of(ZeroTrustAction.BLOCK.name()));
            return;
        }
        if (expression.contains("#ai.needsChallenge()")) {
            dto.setAiActionEnabled(true);
            dto.setAllowedActions(List.of(ZeroTrustAction.CHALLENGE.name()));
            return;
        }
        if (expression.contains("#ai.needsEscalation()")) {
            dto.setAiActionEnabled(true);
            dto.setAllowedActions(List.of(ZeroTrustAction.ESCALATE.name()));
            return;
        }

        Matcher multiMatcher = Pattern.compile("#ai\\.hasActionIn\\(([^)]+)\\)").matcher(expression);
        if (multiMatcher.find()) {
            dto.setAiActionEnabled(true);
            dto.setAllowedActions(extractActionValues(multiMatcher.group(1)));
            return;
        }

        Matcher defaultMatcher = Pattern.compile("#ai\\.hasActionOrDefault\\(([^)]+)\\)").matcher(expression);
        if (defaultMatcher.find()) {
            dto.setAiActionEnabled(true);
            List<String> allActions = extractActionValues(defaultMatcher.group(1));
            if (allActions.size() > 1) {
                dto.setAllowedActions(allActions.subList(1, allActions.size()));
            } else {
                dto.setAllowedActions(allActions);
            }
            return;
        }

        Matcher singleMatcher = Pattern.compile("#ai\\.hasAction\\('([^']+)'\\)").matcher(expression);
        if (singleMatcher.find()) {
            dto.setAiActionEnabled(true);
            dto.setAllowedActions(List.of(singleMatcher.group(1).toUpperCase()));
        }
    }

    private List<String> extractActionValues(String actionsStr) {
        Matcher valueMatcher = Pattern.compile("'([^']+)'").matcher(actionsStr);
        List<String> actions = new ArrayList<>();
        while (valueMatcher.find()) {
            actions.add(valueMatcher.group(1).toUpperCase());
        }
        return actions;
    }

    private void extractCustomSpelCondition(String expression, BusinessPolicyDto dto) {
        String cleaned = expression;

        cleaned = cleaned.replaceAll("\\(hasAuthority\\('[^']++'\\)( or )?\\)+", "");
        cleaned = cleaned.replaceAll("hasAuthority\\('[^']++'\\)( or )?", "");

        cleaned = cleaned.replaceAll("#ai\\.isAllowed\\(\\)", "");
        cleaned = cleaned.replaceAll("#ai\\.isBlocked\\(\\)", "");
        cleaned = cleaned.replaceAll("#ai\\.needsChallenge\\(\\)", "");
        cleaned = cleaned.replaceAll("#ai\\.needsEscalation\\(\\)", "");
        cleaned = cleaned.replaceAll("#ai\\.isPendingAnalysis\\(\\)", "");
        cleaned = cleaned.replaceAll("#ai\\.hasAction\\('[^']*'\\)", "");
        cleaned = cleaned.replaceAll("#ai\\.hasActionIn\\([^)]*\\)", "");
        cleaned = cleaned.replaceAll("#ai\\.hasActionOrDefault\\([^)]*\\)", "");

        cleaned = cleaned.replaceAll("\\s*and\\s+and\\s*", " and ");
        cleaned = cleaned.replaceAll("^\\s*and\\s*", "");
        cleaned = cleaned.replaceAll("\\s*and\\s*$", "");
        cleaned = cleaned.trim();

        cleaned = cleaned.replaceAll("^\\((.*)\\)$", "$1");

        if (StringUtils.hasText(cleaned) && !cleaned.equals("()")) {
            dto.setCustomConditionSpel(cleaned);
        }
    }

    private void validateSpelSafety(String spel) {
        String upper = spel.toUpperCase();
        String[] dangerousPatterns = {
            "T(", "RUNTIME", "EXEC(", "PROCESSBUILDER",
            "GETCLASS(", "FORNAME(", "SYSTEM.", "CLASSLOADER",
            "JAVA.LANG.", "JAVA.IO.", "JAVA.NET."
        };
        for (String pattern : dangerousPatterns) {
            if (upper.contains(pattern)) {
                throw new IllegalArgumentException("SpEL expression contains dangerous pattern: " + pattern);
            }
        }
    }

    private void updateResourceStatusForPermissions(Set<Long> permissionIds) {
        if (CollectionUtils.isEmpty(permissionIds)) return;
        try {
            for (Long permId : permissionIds) {
                permissionRepository.findById(permId).ifPresent(perm -> {
                    ManagedResource resource = perm.getManagedResource();
                    if (resource != null && resource.getStatus() == ManagedResource.Status.PERMISSION_CREATED) {
                        resource.setStatus(ManagedResource.Status.POLICY_CONNECTED);
                    }
                });
            }
        } catch (Exception e) {
            log.error("Failed to update resource status after policy creation", e);
        }
    }
}