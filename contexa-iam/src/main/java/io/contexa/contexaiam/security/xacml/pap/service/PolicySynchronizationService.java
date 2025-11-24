package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexaiam.common.event.dto.RolePermissionsChangedEvent;
import io.contexa.contexaiam.domain.dto.ConditionDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.dto.RuleDto;
import io.contexa.contexaiam.domain.dto.TargetDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class PolicySynchronizationService {

    private final PolicyRepository policyRepository;
    private final RoleRepository roleRepository;
    private final PolicyService policyService;

    /**
     * [핵심 구현] 역할-권한 변경 이벤트를 구독하여 정책을 자동으로 동기화합니다.
     * @param event 역할 변경 이벤트
     */
    @Async
    @EventListener
    @Transactional
    public void handleRolePermissionsChange(RolePermissionsChangedEvent event) {
        log.info("역할(ID: {}) 변경 이벤트 수신. 정책 동기화를 시작합니다.", event.getRoleId());

        // 1. 이벤트로부터 역할 ID를 받아, 관련된 모든 정보(권한, 리소스)를 한 번에 조회합니다.
        Role role = roleRepository.findByIdWithPermissionsAndResources(event.getRoleId())
                .orElseThrow(() -> new IllegalArgumentException("동기화할 역할을 찾을 수 없습니다: " + event.getRoleId()));

        synchronizePolicyForRole(role);
    }

    /**
     * 특정 역할(Role)의 변경사항을 기반으로, 이에 매핑되는 기술 정책(Policy)을
     * 자동으로 생성하거나 업데이트하여 동기화합니다.
     */
    private void synchronizePolicyForRole(Role role) {
        String policyName = "AUTO_POLICY_FOR_" + role.getRoleName();

        // 2. 대상(Target) DTO 목록 생성: 역할이 가진 모든 권한에 연결된 리소스 정보를 추출합니다.
        List<TargetDto> targetDtos = role.getRolePermissions().stream()
                .map(rp -> rp.getPermission().getManagedResource())
                .filter(Objects::nonNull)
                .map(mr -> new TargetDto(
                        mr.getResourceType().name(),
                        mr.getResourceIdentifier(),
                        mr.getHttpMethod() != null ? mr.getHttpMethod().name() : "ANY"
                ))
                .distinct() // 중복된 리소스 대상은 제거
                .toList();

        // 3. SpEL 규칙(Rule) 생성: 역할이 가진 모든 권한을 OR로 연결합니다.
        String permissionsExpression = role.getRolePermissions().stream()
                .map(rp -> rp.getPermission().getName())
                .map(permissionName -> String.format("hasAuthority('%s')", permissionName))
                .collect(Collectors.joining(" or "));

        // 최종 SpEL 조건은 "이 역할을 가졌는가? AND (A권한 OR B권한 OR...)" 형태가 됩니다.
        String finalCondition = String.format("hasAuthority('%s') and (%s)",
                role.getRoleName(),
                StringUtils.hasText(permissionsExpression) ? permissionsExpression : "false" // 권한이 없으면 항상 false
        );

        ConditionDto conditionDto = ConditionDto.builder()
                .expression(finalCondition)
                .authorizationPhase(PolicyCondition.AuthorizationPhase.PRE_AUTHORIZE).build();
        RuleDto ruleDto = RuleDto.builder()
                .description("Auto-sync rule for " + role.getRoleName()).conditions(List.of(conditionDto)).build();

        // 4. 최종 PolicyDto를 구성합니다.
        PolicyDto policyDto = PolicyDto.builder()
                .name(policyName)
                .description(String.format("'%s' 역할을 위한 자동 동기화 정책", role.getRoleDesc()))
                .effect(Policy.Effect.ALLOW)
                .priority(500) // 자동 생성 정책은 중간 우선순위
                .targets(targetDtos)
                .rules(List.of(ruleDto))
                .build();

        // 5. 기존에 자동 생성된 정책이 있는지 이름으로 찾아, 있으면 업데이트, 없으면 새로 생성합니다.
        policyRepository.findByName(policyName)
                .ifPresentOrElse(
                        existingPolicy -> {
                            policyDto.setId(existingPolicy.getId());
                            policyService.updatePolicy(policyDto);
                            log.info("기존 자동 정책(ID: {})을 역할({}) 변경에 따라 업데이트했습니다.", existingPolicy.getId(), role.getRoleName());
                        },
                        () -> {
                            policyService.createPolicy(policyDto);
                            log.info("역할({})에 대한 새로운 자동 정책을 생성했습니다.", role.getRoleName());
                        }
                );
    }
}