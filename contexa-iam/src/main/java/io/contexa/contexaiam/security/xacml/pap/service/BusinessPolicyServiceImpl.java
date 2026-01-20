package io.contexa.contexaiam.security.xacml.pap.service;

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
            throw new IllegalArgumentException("정책을 생성하려면 최소 하나 이상의 역할과 권한이 선택되어야 합니다.");
        }

        
        updateRolePermissionMappings(dto.getRoleIds(), dto.getPermissionIds());
        log.info("'{}' 정책 생성을 위한 RBAC 관계 설정 완료. 대상 역할: {}, 대상 권한: {}", dto.getPolicyName(), dto.getRoleIds(), dto.getPermissionIds());

        Policy policy = new Policy();
        translateAndApplyDtoToPolicy(policy, dto);

        policyEnrichmentService.enrichPolicyWithFriendlyDescription(policy);

        Policy savedPolicy = policyRepository.save(policy);
        authorizationManager.reload();

        log.info("조건부 정책 '{}'(ID: {})이(가) 성공적으로 생성되었습니다.", savedPolicy.getName(), savedPolicy.getId());
        return savedPolicy;
    }

    @Override
    public Policy updatePolicyFromBusinessRule(Long policyId, BusinessPolicyDto dto) {
        Policy existingPolicy = policyRepository.findByIdWithDetails(policyId)
                .orElseThrow(() -> new IllegalArgumentException("Policy not found with id: " + policyId));
        log.info("정책 '{}'(ID: {}) 업데이트 시작.", existingPolicy.getName(), policyId);

        
        updateRolePermissionMappings(dto.getRoleIds(), dto.getPermissionIds());

        translateAndApplyDtoToPolicy(existingPolicy, dto);
        policyEnrichmentService.enrichPolicyWithFriendlyDescription(existingPolicy);

        Policy updatedPolicy = policyRepository.save(existingPolicy);
        authorizationManager.reload();

        log.info("정책 '{}'(ID: {})이(가) 성공적으로 업데이트되었습니다.", updatedPolicy.getName(), updatedPolicy.getId());
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
                    .description("지능형 빌더에서 생성/수정된 동적 규칙")
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

        if (dto.isAiRiskAssessmentEnabled()) {
            allConditions.add(String.format("#ai.assessContext().score >= %.2f", dto.getRequiredTrustScore()));
        }
        if (StringUtils.hasText(dto.getCustomConditionSpel())) {
            allConditions.add("(" + dto.getCustomConditionSpel() + ")");
        }
        if (!CollectionUtils.isEmpty(dto.getConditions())) {
            dto.getConditions().forEach((templateId, params) -> {
                ConditionTemplate template = conditionTemplateRepository.findById(templateId)
                        .orElseThrow(() -> new IllegalArgumentException("조건 템플릿을 찾을 수 없습니다: " + templateId));
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

        log.info("Policy ID {} -> BusinessPolicyDto 변환 완료. 역할: {}, 권한: {}",
                policy.getId(), roleIds.size(), permissionIds.size());

        return dto;
    }

    
    private Set<Long> extractPermissionIds(Policy policy) {
        Set<Long> permissionIds = new HashSet<>();

        for (PolicyTarget target : policy.getTargets()) {
            
            try {
                io.contexa.contexacommon.entity.ManagedResource.ResourceType resourceType =
                        io.contexa.contexacommon.entity.ManagedResource.ResourceType.valueOf(target.getTargetType());

                List<Permission> permissions = permissionRepository.findByResourceTypeAndIdentifier(
                    resourceType,
                    target.getTargetIdentifier()
                );

                permissions.stream()
                    .map(Permission::getId)
                    .forEach(permissionIds::add);

            } catch (IllegalArgumentException e) {
                log.warn("알 수 없는 리소스 타입: {} (대상: {})", target.getTargetType(), target.getTargetIdentifier());
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

        
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("hasAuthority\\('([^']+)'\\)");
        java.util.regex.Matcher matcher = pattern.matcher(spelExpression);

        while (matcher.find()) {
            roleNames.add(matcher.group(1));
        }

        return roleNames;
    }

    
    private void analyzeConditions(Policy policy, BusinessPolicyDto dto) {
        for (PolicyRule rule : policy.getRules()) {
            for (PolicyCondition condition : rule.getConditions()) {
                String expression = condition.getExpression();
                if (StringUtils.hasText(expression)) {
                    
                    analyzeAiRiskCondition(expression, dto);

                    
                    extractCustomSpelCondition(expression, dto);
                }
            }
        }
    }

    
    private void analyzeAiRiskCondition(String expression, BusinessPolicyDto dto) {
        
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("#ai\\.assessContext\\(\\)\\.score >= ([0-9\\.]+)");
        java.util.regex.Matcher matcher = pattern.matcher(expression);

        if (matcher.find()) {
            dto.setAiRiskAssessmentEnabled(true);
            try {
                double trustScore = Double.parseDouble(matcher.group(1));
                dto.setRequiredTrustScore(trustScore);
            } catch (NumberFormatException e) {
                log.warn("AI 신뢰도 점수 파싱 실패: {}", matcher.group(1));
                dto.setRequiredTrustScore(0.75); 
            }
        }
    }

    
    private void extractCustomSpelCondition(String expression, BusinessPolicyDto dto) {
        
        String cleaned = expression;

        
        cleaned = cleaned.replaceAll("\\(hasAuthority\\('[^']++'\\)( or )?\\)+", "");
        cleaned = cleaned.replaceAll("hasAuthority\\('[^']++'\\)( or )?", "");

        
        cleaned = cleaned.replaceAll("#ai\\.assessContext\\(\\)\\.score >= [0-9\\.]+", "");

        
        cleaned = cleaned.replaceAll("\\s*and\\s+and\\s*", " and ");
        cleaned = cleaned.replaceAll("^\\s*and\\s*", "");
        cleaned = cleaned.replaceAll("\\s*and\\s*$", "");
        cleaned = cleaned.trim();

        
        cleaned = cleaned.replaceAll("^\\((.*)\\)$", "$1");

        if (StringUtils.hasText(cleaned) && !cleaned.equals("()")) {
            dto.setCustomConditionSpel(cleaned);
        }
    }
}