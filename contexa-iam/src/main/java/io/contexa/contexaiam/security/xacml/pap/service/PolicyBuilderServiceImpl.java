package io.contexa.contexaiam.security.xacml.pap.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.web.studio.dto.SimulationResultDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.entity.PolicyTemplate;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.PolicyTemplateRepository;
import io.contexa.contexaiam.security.core.CustomUserDetails;
import io.contexa.contexaiam.security.xacml.pap.dto.*;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * [최종 구현] 모든 Mock 및 Placeholder를 제거하고, 실제 DB 연동 및 비즈니스 로직을 포함한 완전한 구현체입니다.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PolicyBuilderServiceImpl implements PolicyBuilderService {

    private final PolicyRepository policyRepository;
    private final UserRepository userRepository;
    private final PermissionRepository permissionRepository;
    private final PolicyTemplateRepository policyTemplateRepository;
    private final PolicyService policyService;
    private final ModelMapper modelMapper;
    private final ObjectMapper objectMapper;
    private final SpelExpressionParser expressionParser = new SpelExpressionParser();
    private static final Pattern AUTHORITY_PATTERN = Pattern.compile("hasAuthority\\('([^']*)'\\)");


    @Override
    @Transactional(readOnly = true)
    public List<PolicyTemplateDto> getAvailableTemplates(PolicyContext context) {
        List<PolicyTemplate> templates = policyTemplateRepository.findAll();
        return templates.stream()
                .map(this::convertTemplateEntityToDto)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public Policy buildPolicyFromVisualComponents(VisualPolicyDto dto) {
        Policy policy = Policy.builder()
                .name(dto.name()).description(dto.description()).effect(dto.effect()).priority(500).build();

        List<String> conditions = new ArrayList<>();
        String subjectExpr = dto.subjects().stream()
                .map(s -> String.format("hasAuthority('%s_%d')", s.type(), s.id()))
                .collect(Collectors.joining(" or "));
        if (!subjectExpr.isEmpty()) conditions.add("(" + subjectExpr + ")");

        // VisualPolicyDto에서 전달된 permissionId로 Permission 목록을 조회합니다.
        Set<Long> permissionIds = dto.permissions().stream()
                .map(VisualPolicyDto.PermissionIdentifier::id)
                .collect(Collectors.toSet());
        List<Permission> perms = permissionRepository.findAllById(permissionIds);

        String permExpr = perms.stream().map(p -> String.format("hasAuthority('%s')", p.getName()))
                .collect(Collectors.joining(" and "));
        if(!permExpr.isEmpty()) conditions.add("(" + permExpr + ")");

        PolicyRule rule = PolicyRule.builder().policy(policy)
                .description("Visually built rule").build();
        rule.setConditions(conditions.stream().map(expr -> PolicyCondition.builder().expression(expr).rule(rule).build()).collect(Collectors.toSet()));

        // [오류 수정] getFunctions() 대신 getManagedResource()를 직접 사용하여 PolicyTarget 생성
        Set<PolicyTarget> targets = perms.stream()
                .map(Permission::getManagedResource) // 각 Permission에 직접 연결된 ManagedResource를 가져옴
                .filter(Objects::nonNull) // 혹시 모를 null 값 방지
                .map(mr -> PolicyTarget.builder()
                        .policy(policy)
                        .targetType(mr.getResourceType().name())
                        .httpMethod(mr.getHttpMethod() != null ? mr.getHttpMethod().name() : null)
                        .targetIdentifier(mr.getResourceIdentifier())
                        .build())
                .collect(Collectors.toSet());

        policy.setRules(Set.of(rule));
        policy.setTargets(targets);

        // PolicyService를 통해 DTO로 변환하여 생성 요청
        PolicyDto policyDto = modelMapper.map(policy, PolicyDto.class);
        return policyService.createPolicy(policyDto);
    }

    /**
     * [최종 로직 구현] 실제 DB 조회 및 SpEL 평가를 통해 정책 변경의 영향을 시뮬레이션합니다.
     */
    @Override
    @Transactional(readOnly = true)
    public SimulationResultDto simulatePolicy(Policy policyToSimulate, SimulationContext context) {
        if (context == null || CollectionUtils.isEmpty(context.userIds())) {
            return new SimulationResultDto("시뮬레이션 대상 사용자가 지정되지 않았습니다.", Collections.emptyList());
        }

        List<SimulationResultDto.ImpactDetail> allImpacts = new ArrayList<>();
        List<Users> targetUsers = userRepository.findAllById(context.userIds());

        for (Users user : targetUsers) {
            CustomUserDetails userDetails = new CustomUserDetails(user);
            Authentication authentication = new UsernamePasswordAuthenticationToken(user.getUsername(), null, userDetails.getAuthorities());

            Set<String> beforePermissions = getEffectivePermissions(authentication, null);
            Set<String> afterPermissions = getEffectivePermissions(authentication, policyToSimulate);

            Set<String> gained = new HashSet<>(afterPermissions);
            gained.removeAll(beforePermissions);
            gained.forEach(permName -> {
                // 권한 이름으로 Permission 엔티티를 조회하여 상세 정보 획득
                Permission p = permissionRepository.findByName(permName).orElse(null);
                String description = (p != null && p.getDescription() != null) ? p.getDescription() : permName;

                allImpacts.add(new SimulationResultDto.ImpactDetail(
                        user.getName(),
                        "USER",
                        permName,       // 기술 이름 전달
                        description,    // 사용자 친화적 설명 전달
                        SimulationResultDto.ImpactType.PERMISSION_GAINED,
                        policyToSimulate.getName()
                ));
            });

            Set<String> lost = new HashSet<>(beforePermissions);
            lost.removeAll(afterPermissions);

            // [수정] 상실(LOST) 권한 처리 로직
            lost.forEach(permName -> {
                // 권한 이름으로 Permission 엔티티를 조회하여 상세 정보 획득
                Permission p = permissionRepository.findByName(permName).orElse(null);
                String description = (p != null && p.getDescription() != null) ? p.getDescription() : permName;

                allImpacts.add(new SimulationResultDto.ImpactDetail(
                        user.getName(),
                        "USER",
                        permName,       // 기술 이름 전달
                        description,    // 사용자 친화적 설명 전달
                        SimulationResultDto.ImpactType.PERMISSION_LOST,
                        policyToSimulate.getName()
                ));
            });
        }

        String summary = String.format("총 %d명의 사용자에 대해 %d개의 권한 변경이 예상됩니다.", targetUsers.size(), allImpacts.size());
        return new SimulationResultDto(summary, allImpacts);
    }

    /**
     * [최종 로직 구현] 실제 DB 조회를 통해 정책 충돌을 감지합니다.
     */
    @Override
    public List<PolicyConflictDto> detectConflicts(Policy newPolicy) {
        List<PolicyConflictDto> conflicts = new ArrayList<>();
        List<Policy> existingPolicies = policyRepository.findAllWithDetails();
        Set<String> newPolicyTargetSignatures = getTargetSignatures(newPolicy);

        for (Policy existingPolicy : existingPolicies) {
            if (newPolicy.getId() != null && newPolicy.getId().equals(existingPolicy.getId())) {
                continue;
            }

            if (newPolicy.getEffect() != existingPolicy.getEffect()) {
                Set<String> existingPolicyTargetSignatures = getTargetSignatures(existingPolicy);
                if (!Collections.disjoint(newPolicyTargetSignatures, existingPolicyTargetSignatures)) {
                    conflicts.add(new PolicyConflictDto(
                            newPolicy.getId(), newPolicy.getName(),
                            existingPolicy.getId(), existingPolicy.getName(),
                            "동일한 대상에 대해 허용(ALLOW)과 거부(DENY) 정책이 충돌합니다."
                    ));
                }
            }
        }
        return conflicts;
    }

    private PolicyTemplateDto convertTemplateEntityToDto(PolicyTemplate template) {
        try {
            PolicyDto draft = objectMapper.readValue(template.getPolicyDraftJson(), PolicyDto.class);
            return new PolicyTemplateDto(template.getTemplateId(), template.getName(), template.getDescription(), draft);
        } catch (IOException e) {
            log.error("Failed to deserialize policy draft for template ID: {}", template.getTemplateId(), e);
            return null;
        }
    }

    private Set<String> getTargetSignatures(Policy policy) {
        return policy.getTargets().stream()
                .map(t -> t.getTargetType() + ":" + t.getTargetIdentifier())
                .collect(Collectors.toSet());
    }

    private Set<String> getEffectivePermissions(Authentication authentication, Policy temporaryPolicy) {
        Set<String> permissions = authentication.getAuthorities().stream()
                .map(Object::toString).collect(Collectors.toSet());
        if (temporaryPolicy != null && doesPolicyApply(temporaryPolicy, authentication)) {
            Set<String> permissionsFromPolicy = getPermissionsFromPolicyRule(temporaryPolicy);
            if (temporaryPolicy.getEffect() == Policy.Effect.ALLOW) permissions.addAll(permissionsFromPolicy);
            else permissions.removeAll(permissionsFromPolicy);
        }
        return permissions;
    }

    private Set<String> getPermissionsFromPolicyRule(Policy policy) {
        Set<String> perms = new HashSet<>();
        policy.getRules().stream()
                .flatMap(r -> r.getConditions().stream())
                .map(PolicyCondition::getExpression)
                .forEach(expr -> {
                    Matcher matcher = AUTHORITY_PATTERN.matcher(expr);
                    while (matcher.find()) {
                        String authority = matcher.group(1);
                        if (authority.startsWith("PERM_")) {
                            perms.add(authority);
                        }
                    }
                });
        return perms;
    }

    private boolean doesPolicyApply(Policy policy, Authentication authentication) {
        StandardEvaluationContext context = new StandardEvaluationContext(authentication);
        context.setVariable("authentication", authentication);

        String condition = policy.getRules().stream()
                .flatMap(r -> r.getConditions().stream())
                .map(c -> "(" + c.getExpression() + ")")
                .collect(Collectors.joining(" && "));

        if (condition.isEmpty()) return true;

        try {
            Expression expression = expressionParser.parseExpression(condition);
            return Boolean.TRUE.equals(expression.getValue(context, Boolean.class));
        } catch (Exception e) {
            log.error("Error evaluating SpEL for simulation: {}", e.getMessage());
            return false;
        }
    }
}
