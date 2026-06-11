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
    @Transactional(transactionManager = "contexaTransactionManager")
    public void handleRolePermissionsChange(RolePermissionsChangedEvent event) {

        Role role = roleRepository.findByIdWithPermissionsAndResources(event.getRoleId())
                .orElseThrow(() -> new IllegalArgumentException("Role not found for synchronization: " + event.getRoleId()));

        synchronizePolicyForRole(role);
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void cleanupAutoPolicy(String roleName) {
        String policyName = "AUTO_POLICY_FOR_" + roleName;
        policyRepository.findByName(policyName).ifPresent(policy -> {
            policyService.deletePolicy(policy.getId(), "Auto-cleanup: role deleted - " + roleName);
        });
    }

    private void synchronizePolicyForRole(Role role) {
        String policyName = "AUTO_POLICY_FOR_" + role.getRoleName();

        List<TargetDto> targetDtos = role.getRolePermissions().stream()
                .map(rp -> rp.getPermission().getManagedResource())
                .filter(Objects::nonNull)
                .map(mr -> TargetDto.builder()
                        .targetType(mr.getResourceType().name())
                        .targetIdentifier(mr.getResourceIdentifier())
                        .httpMethod(mr.getHttpMethod() != null ? mr.getHttpMethod().name() : "ANY")
                        .build())
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
                .description(String.format("Auto-synchronized policy for role '%s'", role.getRoleDesc()))
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
                                                    },
                        () -> {
                            policyService.createPolicy(policyDto);
                                                    }
                );
    }
}