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
package io.contexa.contexaiam.security.xacml.pap.analysis;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.Mock;
import org.mockito.quality.Strictness;
import org.springframework.context.MessageSource;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PolicyDuplicateDetectorTest {

    @Mock
    private PolicyRepository policyRepository;

    @Mock
    private RoleHierarchy roleHierarchy;

    @Mock
    private MessageSource messageSource;

    private PolicyDuplicateDetector detector;

    @BeforeEach
    void setUp() {
        when(messageSource.getMessage(any(String.class), any(), any(Locale.class)))
                .thenAnswer(inv -> {
                    String code = inv.getArgument(0);
                    return switch (code) {
                        case "msg.policy.duplicate.exact" -> "Exact duplicate: identical targets, conditions, and effect";
                        case "msg.policy.duplicate.semantic" -> "Semantic duplicate: equivalent after SpEL normalization";
                        case "msg.policy.duplicate.subset" -> "Subset: existing policy already covers this policy";
                        default -> code;
                    };
                });
        detector = new PolicyDuplicateDetector(policyRepository, roleHierarchy, messageSource);
    }

    private Policy buildPolicyWithCondition(Long id, String name, Policy.Effect effect,
                                             String targetPath, String httpMethod, String expression) {
        Policy policy = Policy.builder().id(id).name(name).effect(effect).priority(100).isActive(true).build();
        PolicyTarget target = PolicyTarget.builder()
                .policy(policy).targetType("URL").targetIdentifier(targetPath).httpMethod(httpMethod).build();
        policy.getTargets().add(target);

        PolicyRule rule = PolicyRule.builder().policy(policy).description("rule").build();
        PolicyCondition cond = PolicyCondition.builder().rule(rule).expression(expression).build();
        rule.setConditions(Set.of(cond));
        policy.getRules().add(rule);
        return policy;
    }

    private void stubExisting(Policy... policies) {
        when(policyRepository.findAllWithDetails()).thenReturn(List.of(policies));
    }

    @Nested
    @DisplayName("EXACT 중복 감지")
    class ExactDuplicate {

        @Test
        @DisplayName("동일 타겟 + 동일 조건 + 동일 effect -> EXACT 중복")
        void identicalPolicy() {
            Policy existing = buildPolicyWithCondition(1L, "existing", Policy.Effect.ALLOW,
                    "/api/users", "GET", "hasAuthority('ROLE_ADMIN')");
            stubExisting(existing);

            Policy candidate = buildPolicyWithCondition(null, "candidate", Policy.Effect.ALLOW,
                    "/api/users", "GET", "hasAuthority('ROLE_ADMIN')");

            List<DuplicatePolicyDto> dups = detector.detect(candidate);

            assertThat(dups).hasSize(1);
            assertThat(dups.get(0).reason()).contains("Exact duplicate");
        }

        @Test
        @DisplayName("effect가 다르면 EXACT 중복 아님")
        void differentEffect() {
            Policy existing = buildPolicyWithCondition(1L, "existing", Policy.Effect.ALLOW,
                    "/api/users", "GET", "hasAuthority('ROLE_ADMIN')");
            stubExisting(existing);

            Policy candidate = buildPolicyWithCondition(null, "candidate", Policy.Effect.DENY,
                    "/api/users", "GET", "hasAuthority('ROLE_ADMIN')");

            List<DuplicatePolicyDto> dups = detector.detect(candidate);

            assertThat(dups).isEmpty();
        }

        @Test
        @DisplayName("조건이 다르면 EXACT 중복 아님")
        void differentCondition() {
            Policy existing = buildPolicyWithCondition(1L, "existing", Policy.Effect.ALLOW,
                    "/api/users", "GET", "hasAuthority('ROLE_ADMIN')");
            stubExisting(existing);

            Policy candidate = buildPolicyWithCondition(null, "candidate", Policy.Effect.ALLOW,
                    "/api/users", "GET", "hasAuthority('ROLE_USER')");

            List<DuplicatePolicyDto> dups = detector.detect(candidate);

            assertThat(dups).isEmpty();
        }
    }

    @Nested
    @DisplayName("SEMANTIC 중복 감지")
    class SemanticDuplicate {

        @Test
        @DisplayName("hasRole('ADMIN') vs hasAuthority('ROLE_ADMIN') -> SEMANTIC 중복")
        void hasRoleVsHasAuthority() {
            Policy existing = buildPolicyWithCondition(1L, "existing", Policy.Effect.ALLOW,
                    "/api/users", "GET", "hasAuthority('ROLE_ADMIN')");
            stubExisting(existing);

            Policy candidate = buildPolicyWithCondition(null, "candidate", Policy.Effect.ALLOW,
                    "/api/users", "GET", "hasRole('ADMIN')");

            List<DuplicatePolicyDto> dups = detector.detect(candidate);

            assertThat(dups).hasSize(1);
            assertThat(dups.get(0).reason()).contains("Semantic duplicate");
        }

        @Test
        @DisplayName("hasRole('ROLE_ADMIN') vs hasAuthority('ROLE_ADMIN') -> SEMANTIC 중복")
        void hasRoleWithPrefix() {
            Policy existing = buildPolicyWithCondition(1L, "existing", Policy.Effect.ALLOW,
                    "/api/data", "POST", "hasAuthority('ROLE_ADMIN')");
            stubExisting(existing);

            Policy candidate = buildPolicyWithCondition(null, "candidate", Policy.Effect.ALLOW,
                    "/api/data", "POST", "hasRole('ROLE_ADMIN')");

            List<DuplicatePolicyDto> dups = detector.detect(candidate);

            assertThat(dups).hasSize(1);
        }
    }

    @Nested
    @DisplayName("SUBSET 중복 감지")
    class SubsetDuplicate {

        @Test
        @DisplayName("기존 정책이 후보의 타겟과 조건을 모두 포함 -> SUBSET")
        void existingCoversCandidate() {
            Policy existing = Policy.builder().id(1L).name("existing").effect(Policy.Effect.ALLOW).priority(100).isActive(true).build();
            PolicyTarget t1 = PolicyTarget.builder().policy(existing).targetType("URL").targetIdentifier("/api/users").httpMethod("GET").build();
            PolicyTarget t2 = PolicyTarget.builder().policy(existing).targetType("URL").targetIdentifier("/api/orders").httpMethod("POST").build();
            existing.getTargets().addAll(Set.of(t1, t2));
            PolicyRule rule = PolicyRule.builder().policy(existing).build();
            PolicyCondition c1 = PolicyCondition.builder().rule(rule).expression("hasAuthority('ROLE_ADMIN')").build();
            PolicyCondition c2 = PolicyCondition.builder().rule(rule).expression("hasAuthority('ROLE_USER')").build();
            rule.setConditions(Set.of(c1, c2));
            existing.getRules().add(rule);
            stubExisting(existing);

            Policy candidate = buildPolicyWithCondition(null, "candidate", Policy.Effect.ALLOW,
                    "/api/users", "GET", "hasAuthority('ROLE_ADMIN')");

            List<DuplicatePolicyDto> dups = detector.detect(candidate);

            assertThat(dups).isNotEmpty();
            assertThat(dups.stream().anyMatch(d -> d.reason().contains("Subset"))).isTrue();
        }
    }

    @Nested
    @DisplayName("필터링 및 엣지 케이스")
    class EdgeCases {

        @Test
        @DisplayName("자기 자신과는 비교하지 않음")
        void skipSelf() {
            Policy existing = buildPolicyWithCondition(5L, "policy", Policy.Effect.ALLOW,
                    "/api/users", "GET", "hasAuthority('ROLE_ADMIN')");
            stubExisting(existing);

            Policy candidate = buildPolicyWithCondition(5L, "policy", Policy.Effect.ALLOW,
                    "/api/users", "GET", "hasAuthority('ROLE_ADMIN')");

            List<DuplicatePolicyDto> dups = detector.detect(candidate);

            assertThat(dups).isEmpty();
        }

        @Test
        @DisplayName("비활성 정책은 비교 대상에서 제외됨")
        void skipInactive() {
            Policy existing = buildPolicyWithCondition(1L, "inactive", Policy.Effect.ALLOW,
                    "/api/users", "GET", "hasAuthority('ROLE_ADMIN')");
            existing.setIsActive(false);
            stubExisting(existing);

            Policy candidate = buildPolicyWithCondition(null, "candidate", Policy.Effect.ALLOW,
                    "/api/users", "GET", "hasAuthority('ROLE_ADMIN')");

            List<DuplicatePolicyDto> dups = detector.detect(candidate);

            assertThat(dups).isEmpty();
        }

        @Test
        @DisplayName("기존 정책이 없으면 중복 없음")
        void noExisting() {
            stubExisting();

            Policy candidate = buildPolicyWithCondition(null, "candidate", Policy.Effect.ALLOW,
                    "/api/users", "GET", "hasAuthority('ROLE_ADMIN')");

            List<DuplicatePolicyDto> dups = detector.detect(candidate);

            assertThat(dups).isEmpty();
        }
    }
}
