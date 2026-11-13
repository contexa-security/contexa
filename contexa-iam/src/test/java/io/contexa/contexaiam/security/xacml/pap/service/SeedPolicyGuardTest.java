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

import io.contexa.contexaiam.domain.dto.ConditionDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.dto.RuleDto;
import io.contexa.contexaiam.domain.dto.TargetDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** D46: the seed policies 1 (sign-in page) and 2 (admin area) are kept, and no edit widens them. */
class SeedPolicyGuardTest {

    private static final String ADMIN_AREA = "/contexa/admin/**";
    private static final String LOGIN = "/contexa/admin/login";

    @Test
    @DisplayName("policies 1 and 2 are not removed; any other policy is")
    void onlyTheSeedPoliciesAreKept() {
        assertThat(SeedPolicyGuard.refuseRemoval(1L)).contains(SeedPolicyGuard.REMOVAL_REFUSED);
        assertThat(SeedPolicyGuard.refuseRemoval(2L)).contains(SeedPolicyGuard.REMOVAL_REFUSED);
        assertThat(SeedPolicyGuard.refuseRemoval(3L)).isEmpty();
        assertThat(SeedPolicyGuard.refuseRemoval(null)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "hasRole('ADMIN')",
            "hasRole('ROLE_ADMIN')",
            "hasAuthority('ROLE_ADMIN')",
            "hasRole('ADMIN') and isFullyAuthenticated()",
            "isFullyAuthenticated() and (hasRole('ADMIN'))",
            "hasIpAddress('10.0.0.0/8') and hasRole('ADMIN') and isFullyAuthenticated()"
    })
    @DisplayName("policy 2 may keep or narrow hasRole('ADMIN')")
    void policyTwoMayBeNarrowed(String condition) {
        assertThat(SeedPolicyGuard.refuseChange(2L, adminArea(condition))).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "isAuthenticated()",
            "permitAll",
            "hasRole('ADMIN') or isAuthenticated()",
            "!hasRole('ADMIN')",
            "hasRole('USER')",
            "hasAnyRole('ADMIN','USER')",
            "hasAuthority('ADMIN')",
            "not a (valid expression"
    })
    @DisplayName("policy 2 may not be widened away from hasRole('ADMIN')")
    void policyTwoMayNotBeWidened(String condition) {
        assertThat(SeedPolicyGuard.refuseChange(2L, adminArea(condition))).contains(SeedPolicyGuard.ADMIN_CHANGE_REFUSED);
    }

    @Test
    @DisplayName("policy 2 keeps its effect, its target on the whole admin area for any method, and a condition")
    void policyTwoKeepsItsEffectTargetAndCondition() {
        PolicyDto deny = adminArea("hasRole('ADMIN')");
        deny.setEffect(Policy.Effect.DENY);
        PolicyDto narrowerTarget = dto(Policy.Effect.ALLOW, "URL", "/contexa/admin/blogs/**", "ALL", "hasRole('ADMIN')");
        PolicyDto oneMethod = dto(Policy.Effect.ALLOW, "URL", ADMIN_AREA, "GET", "hasRole('ADMIN')");
        PolicyDto noCondition = adminArea("hasRole('ADMIN')");
        noCondition.setRules(List.of());

        assertThat(SeedPolicyGuard.refuseChange(2L, deny)).contains(SeedPolicyGuard.ADMIN_CHANGE_REFUSED);
        assertThat(SeedPolicyGuard.refuseChange(2L, narrowerTarget)).contains(SeedPolicyGuard.ADMIN_CHANGE_REFUSED);
        assertThat(SeedPolicyGuard.refuseChange(2L, oneMethod)).contains(SeedPolicyGuard.ADMIN_CHANGE_REFUSED);
        assertThat(SeedPolicyGuard.refuseChange(2L, noCondition)).contains(SeedPolicyGuard.ADMIN_CHANGE_REFUSED);

        PolicyDto moreTargets = adminArea("hasRole('ADMIN')");
        moreTargets.setTargets(List.of(target("URL", ADMIN_AREA, "ANY"), target("URL", "/ops/**", "ANY")));
        assertThat(SeedPolicyGuard.refuseChange(2L, moreTargets)).isEmpty();
    }

    @Test
    @DisplayName("policy 1 stays an ALLOW policy on the sign-in page only")
    void policyOneStaysOnTheSignInPage() {
        assertThat(SeedPolicyGuard.refuseChange(1L, dto(Policy.Effect.ALLOW, "URL", LOGIN, "ANY", "permitAll")))
                .isEmpty();

        PolicyDto spread = dto(Policy.Effect.ALLOW, "URL", LOGIN, "ANY", "permitAll");
        spread.setTargets(List.of(target("URL", LOGIN, "ANY"), target("URL", ADMIN_AREA, "ANY")));
        assertThat(SeedPolicyGuard.refuseChange(1L, spread)).contains(SeedPolicyGuard.LOGIN_CHANGE_REFUSED);
        assertThat(SeedPolicyGuard.refuseChange(1L, dto(Policy.Effect.DENY, "URL", LOGIN, "ANY", "permitAll")))
                .contains(SeedPolicyGuard.LOGIN_CHANGE_REFUSED);
        PolicyDto noTarget = dto(Policy.Effect.ALLOW, "URL", LOGIN, "ANY", "permitAll");
        noTarget.setTargets(List.of());
        assertThat(SeedPolicyGuard.refuseChange(1L, noTarget)).contains(SeedPolicyGuard.LOGIN_CHANGE_REFUSED);
    }

    @Test
    @DisplayName("any other policy may be edited freely")
    void otherPoliciesAreNotGuarded() {
        assertThat(SeedPolicyGuard.refuseChange(7L, dto(Policy.Effect.DENY, "URL", "/x", "GET", "permitAll"))).isEmpty();
    }

    @Test
    @DisplayName("the policy as it is about to be saved (business rule edit) is checked the same way")
    void theEntityIsCheckedTheSameWay() {
        assertThat(SeedPolicyGuard.refuseChange(entity(2L, "isAuthenticated()")))
                .contains(SeedPolicyGuard.ADMIN_CHANGE_REFUSED);
        assertThat(SeedPolicyGuard.refuseChange(entity(2L, "hasRole('ADMIN')"))).isEmpty();
        assertThat(SeedPolicyGuard.refuseChange(entity(9L, "isAuthenticated()"))).isEmpty();
    }

    private static Policy entity(long id, String condition) {
        Policy policy = Policy.builder().id(id).name("p").effect(Policy.Effect.ALLOW).build();
        policy.addTarget(PolicyTarget.builder().targetType("URL").targetIdentifier(ADMIN_AREA).httpMethod(null).build());
        PolicyRule rule = PolicyRule.builder().build();
        rule.addCondition(PolicyCondition.builder().expression(condition).build());
        policy.addRule(rule);
        return policy;
    }

    private static PolicyDto adminArea(String condition) {
        return dto(Policy.Effect.ALLOW, "URL", ADMIN_AREA, "ALL", condition);
    }

    private static PolicyDto dto(Policy.Effect effect, String type, String identifier, String method,
                                 String condition) {
        return PolicyDto.builder()
                .name("p")
                .effect(effect)
                .targets(List.of(target(type, identifier, method)))
                .rules(List.of(new RuleDto("rule", List.of(new ConditionDto(condition,
                        PolicyCondition.AuthorizationPhase.PRE_AUTHORIZE)))))
                .build();
    }

    private static TargetDto target(String type, String identifier, String method) {
        return TargetDto.builder().targetType(type).targetIdentifier(identifier).httpMethod(method).build();
    }
}
