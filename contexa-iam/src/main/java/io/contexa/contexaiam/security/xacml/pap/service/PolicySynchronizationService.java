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

    
    @Async
    @EventListener
    @Transactional
    public void handleRolePermissionsChange(RolePermissionsChangedEvent event) {
        log.info("역할(ID: {}) 변경 이벤트 수신. 정책 동기화를 시작합니다.", event.getRoleId());

        
        Role role = roleRepository.findByIdWithPermissionsAndResources(event.getRoleId())
                .orElseThrow(() -> new IllegalArgumentException("동기화할 역할을 찾을 수 없습니다: " + event.getRoleId()));

        synchronizePolicyForRole(role);
    }

    
    private void synchronizePolicyForRole(Role role) {
        String policyName = "AUTO_POLICY_FOR_" + role.getRoleName();

        
        List<TargetDto> targetDtos = role.getRolePermissions().stream()
                .map(rp -> rp.getPermission().getManagedResource())
                .filter(Objects::nonNull)
                .map(mr -> new TargetDto(
                        mr.getResourceType().name(),
                        mr.getResourceIdentifier(),
                        mr.getHttpMethod() != null ? mr.getHttpMethod().name() : "ANY"
                ))
                .distinct() 
                .toList();

        
        String permissionsExpression = role.getRolePermissions().stream()
                .map(rp -> rp.getPermission().getName())
                .map(permissionName -> String.format("hasAuthority('%s')", permissionName))
                .collect(Collectors.joining(" or "));

        
        String finalCondition = String.format("hasAuthority('%s') and (%s)",
                role.getRoleName(),
                StringUtils.hasText(permissionsExpression) ? permissionsExpression : "false" 
        );

        ConditionDto conditionDto = ConditionDto.builder()
                .expression(finalCondition)
                .authorizationPhase(PolicyCondition.AuthorizationPhase.PRE_AUTHORIZE).build();
        RuleDto ruleDto = RuleDto.builder()
                .description("Auto-sync rule for " + role.getRoleName()).conditions(List.of(conditionDto)).build();

        
        PolicyDto policyDto = PolicyDto.builder()
                .name(policyName)
                .description(String.format("'%s' 역할을 위한 자동 동기화 정책", role.getRoleDesc()))
                .effect(Policy.Effect.ALLOW)
                .priority(500) 
                .targets(targetDtos)
                .rules(List.of(ruleDto))
                .build();

        
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