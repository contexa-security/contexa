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

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.MessageSource;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PolicyConflictAnalyzerTest {

    @Mock
    private PolicyRepository policyRepository;

    @Mock
    private MessageSource messageSource;

    private PolicyConflictAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        when(messageSource.getMessage(any(String.class), any(), any(java.util.Locale.class))).thenAnswer(inv -> inv.getArgument(0));
        analyzer = new PolicyConflictAnalyzer(policyRepository, messageSource);
    }

    // ── helpers ──────────────────────────────────────────────────

    private Policy buildPolicy(Long id, String name, Policy.Effect effect, boolean active) {
        return Policy.builder()
                .id(id).name(name).effect(effect).priority(100).isActive(active).build();
    }

    private PolicyTarget buildUrlTarget(Policy policy, String path, String httpMethod) {
        PolicyTarget target = PolicyTarget.builder()
                .policy(policy).targetType("URL")
                .targetIdentifier(path).httpMethod(httpMethod).build();
        policy.getTargets().add(target);
        return target;
    }

    private PolicyTarget buildMethodTarget(Policy policy, String methodId) {
        PolicyTarget target = PolicyTarget.builder()
                .policy(policy).targetType("METHOD")
                .targetIdentifier(methodId).build();
        policy.getTargets().add(target);
        return target;
    }

    private void stubExisting(Policy... policies) {
        when(policyRepository.findAllWithDetails()).thenReturn(List.of(policies));
    }

    // ── 1. 정확한 타겟 충돌 ─────────────────────────────────────

    @Nested
    @DisplayName("정확한 타겟 충돌 감지")
    class ExactTargetConflict {

        @Test
        @DisplayName("동일 URL + 동일 HTTP method + 반대 effect -> CRITICAL")
        void sameUrlSameMethodOppositeEffect() {
            Policy existing = buildPolicy(1L, "existing", Policy.Effect.DENY, true);
            buildUrlTarget(existing, "/api/users", "GET");
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "candidate", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/users", "GET");

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).hasSize(1);
            assertThat(conflicts.get(0).severity()).isEqualTo(Severity.CRITICAL);
            assertThat(conflicts.get(0).existingPolicyName()).isEqualTo("existing");
        }

        @Test
        @DisplayName("동일 URL + 동일 HTTP method + 동일 effect -> 충돌 없음")
        void sameUrlSameMethodSameEffect() {
            Policy existing = buildPolicy(1L, "existing", Policy.Effect.ALLOW, true);
            buildUrlTarget(existing, "/api/users", "GET");
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "candidate", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/users", "GET");

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).isEmpty();
        }

        @Test
        @DisplayName("동일 URL + 양쪽 null(ANY) method + 반대 effect -> CRITICAL")
        void sameUrlBothAnyMethodOppositeEffect() {
            Policy existing = buildPolicy(1L, "existing", Policy.Effect.DENY, true);
            buildUrlTarget(existing, "/api/orders", null);
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "candidate", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/orders", null);

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).hasSize(1);
            assertThat(conflicts.get(0).severity()).isEqualTo(Severity.CRITICAL);
        }

        @Test
        @DisplayName("동일 METHOD 타겟 + 반대 effect -> CRITICAL")
        void sameMethodTargetOppositeEffect() {
            Policy existing = buildPolicy(1L, "existing", Policy.Effect.DENY, true);
            buildMethodTarget(existing, "com.example.Service.doAction()");
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "candidate", Policy.Effect.ALLOW, true);
            buildMethodTarget(candidate, "com.example.Service.doAction()");

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).hasSize(1);
            assertThat(conflicts.get(0).severity()).isEqualTo(Severity.CRITICAL);
        }
    }

    // ── 2. 와일드카드 패턴 중첩 ─────────────────────────────────

    @Nested
    @DisplayName("와일드카드 패턴 중첩 감지")
    class WildcardOverlap {

        @Test
        @DisplayName("부모 와일드카드 DENY vs 자식 경로 ALLOW -> HIGH")
        void wildcardParentDenyChildAllow() {
            Policy existing = buildPolicy(1L, "deny-all-users", Policy.Effect.DENY, true);
            buildUrlTarget(existing, "/api/users/**", null);
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "allow-me", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/users/me", null);

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).hasSize(1);
            assertThat(conflicts.get(0).severity()).isEqualTo(Severity.HIGH);
        }

        @Test
        @DisplayName("깊은 와일드카드 중첩: /api/** DENY vs /api/admin/settings ALLOW -> HIGH")
        void deepWildcardOverlap() {
            Policy existing = buildPolicy(1L, "deny-api", Policy.Effect.DENY, true);
            buildUrlTarget(existing, "/api/**", null);
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "allow-admin", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/admin/settings", null);

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).hasSize(1);
            assertThat(conflicts.get(0).severity()).isEqualTo(Severity.HIGH);
        }

        @Test
        @DisplayName("서로 다른 경로의 와일드카드는 중첩되지 않음: /api/users/* vs /api/orders/*")
        void noOverlapDifferentPaths() {
            Policy existing = buildPolicy(1L, "deny-users", Policy.Effect.DENY, true);
            buildUrlTarget(existing, "/api/users/*", null);
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "allow-orders", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/orders/*", null);

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).isEmpty();
        }

        @Test
        @DisplayName("후보의 와일드카드가 기존 구체 경로를 포함 -> HIGH")
        void candidateWildcardMatchesExistingSpecific() {
            Policy existing = buildPolicy(1L, "allow-specific", Policy.Effect.ALLOW, true);
            buildUrlTarget(existing, "/api/reports/daily", null);
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "deny-reports", Policy.Effect.DENY, true);
            buildUrlTarget(candidate, "/api/reports/**", null);

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).hasSize(1);
            assertThat(conflicts.get(0).severity()).isEqualTo(Severity.HIGH);
        }
    }

    // ── 3. HTTP method 중첩 ─────────────────────────────────────

    @Nested
    @DisplayName("HTTP method 중첩 감지")
    class HttpMethodOverlap {

        @Test
        @DisplayName("동일 경로, ANY vs GET, 반대 effect -> MEDIUM")
        void anyVsSpecificMethodOppositeEffect() {
            Policy existing = buildPolicy(1L, "deny-all-methods", Policy.Effect.DENY, true);
            buildUrlTarget(existing, "/api/users", "ANY");
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "allow-get", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/users", "GET");

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).hasSize(1);
            assertThat(conflicts.get(0).severity()).isEqualTo(Severity.MEDIUM);
        }

        @Test
        @DisplayName("동일 경로, null(ANY) vs POST, 반대 effect -> MEDIUM")
        void nullVsSpecificMethodOppositeEffect() {
            Policy existing = buildPolicy(1L, "deny-any", Policy.Effect.DENY, true);
            buildUrlTarget(existing, "/api/data", null);
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "allow-post", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/data", "POST");

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).hasSize(1);
            assertThat(conflicts.get(0).severity()).isEqualTo(Severity.MEDIUM);
        }

        @Test
        @DisplayName("동일 경로, GET vs POST, 반대 effect -> 충돌 없음 (method 불일치)")
        void differentSpecificMethods() {
            Policy existing = buildPolicy(1L, "deny-get", Policy.Effect.DENY, true);
            buildUrlTarget(existing, "/api/users", "GET");
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "allow-post", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/users", "POST");

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).isEmpty();
        }

        @Test
        @DisplayName("ALL은 ANY와 동일하게 처리됨")
        void allTreatedAsAny() {
            Policy existing = buildPolicy(1L, "deny-all", Policy.Effect.DENY, true);
            buildUrlTarget(existing, "/api/items", "ALL");
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "allow-delete", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/items", "DELETE");

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).hasSize(1);
            assertThat(conflicts.get(0).severity()).isEqualTo(Severity.MEDIUM);
        }
    }

    // ── 4. 자기 자신 제외 및 비활성 정책 필터링 ─────────────────

    @Nested
    @DisplayName("자기 제외 및 비활성 정책 필터링")
    class FilteringTests {

        @Test
        @DisplayName("수정 시 자기 자신과의 충돌은 무시함")
        void skipSelfOnUpdate() {
            Policy existing = buildPolicy(5L, "my-policy", Policy.Effect.DENY, true);
            buildUrlTarget(existing, "/api/users", "GET");
            stubExisting(existing);

            Policy candidate = buildPolicy(5L, "my-policy", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/users", "GET");

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).isEmpty();
        }

        @Test
        @DisplayName("비활성 상태의 기존 정책은 충돌 검사에서 제외됨")
        void skipInactivePolicies() {
            Policy existing = buildPolicy(1L, "inactive-deny", Policy.Effect.DENY, false);
            buildUrlTarget(existing, "/api/users", "GET");
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "allow-users", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/users", "GET");

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).isEmpty();
        }
    }

    // ── 5. 엣지 케이스 ──────────────────────────────────────────

    @Nested
    @DisplayName("엣지 케이스")
    class EdgeCases {

        @Test
        @DisplayName("타겟이 없는 후보 정책 -> 충돌 없음")
        void candidateNoTargets() {
            Policy existing = buildPolicy(1L, "existing", Policy.Effect.DENY, true);
            buildUrlTarget(existing, "/api/users", "GET");
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "no-target", Policy.Effect.ALLOW, true);

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).isEmpty();
        }

        @Test
        @DisplayName("기존 정책이 없으면 충돌 없음")
        void noExistingPolicies() {
            stubExisting();

            Policy candidate = buildPolicy(null, "candidate", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/users", "GET");

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).isEmpty();
        }

        @Test
        @DisplayName("여러 기존 정책과 동시에 충돌 감지")
        void multipleConflicts() {
            Policy deny1 = buildPolicy(1L, "deny-users", Policy.Effect.DENY, true);
            buildUrlTarget(deny1, "/api/users", "GET");

            Policy deny2 = buildPolicy(2L, "deny-orders", Policy.Effect.DENY, true);
            buildUrlTarget(deny2, "/api/orders", "POST");

            stubExisting(deny1, deny2);

            Policy candidate = buildPolicy(null, "allow-both", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/users", "GET");
            buildUrlTarget(candidate, "/api/orders", "POST");

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).hasSize(2);
            assertThat(conflicts).allMatch(c -> c.severity() == Severity.CRITICAL);
        }

        @Test
        @DisplayName("기존 정책이 여러 타겟을 가질 때 일치하는 타겟만 충돌")
        void multipleTargetsOnExisting() {
            Policy existing = buildPolicy(1L, "deny-both", Policy.Effect.DENY, true);
            buildUrlTarget(existing, "/api/users", "GET");
            buildUrlTarget(existing, "/api/admin", "POST");
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "allow-admin", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/admin", "POST");

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).hasSize(1);
            assertThat(conflicts.get(0).severity()).isEqualTo(Severity.CRITICAL);
        }
    }

    // ── 6. 와일드카드 + method 복합 중첩 ────────────────────────

    @Nested
    @DisplayName("와일드카드와 HTTP method 복합 중첩")
    class CombinedOverlap {

        @Test
        @DisplayName("와일드카드 경로 + ANY method vs 구체 경로 + 특정 method -> HIGH (와일드카드 우선)")
        void wildcardPathAnyMethodVsSpecific() {
            Policy existing = buildPolicy(1L, "deny-wildcard", Policy.Effect.DENY, true);
            buildUrlTarget(existing, "/api/**", null);
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "allow-specific", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/users/123", "GET");

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).hasSize(1);
            assertThat(conflicts.get(0).severity()).isEqualTo(Severity.HIGH);
        }

        @Test
        @DisplayName("와일드카드 경로 + 특정 method vs 구체 경로 + 다른 method -> 충돌 없음")
        void wildcardPathSpecificMethodVsDifferentMethod() {
            Policy existing = buildPolicy(1L, "deny-wildcard-get", Policy.Effect.DENY, true);
            buildUrlTarget(existing, "/api/users/*", "GET");
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "allow-post", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/users/1", "POST");

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).isEmpty();
        }
    }

    // ── 7. 충돌 설명 정확성 ─────────────────────────────────────

    @Nested
    @DisplayName("충돌 설명 정확성 검증")
    class DescriptionTests {

        @Test
        @DisplayName("충돌 설명에 양쪽 effect 이름과 타겟 경로가 포함됨")
        void descriptionContainsEffectsAndPaths() {
            Policy existing = buildPolicy(1L, "deny-users", Policy.Effect.DENY, true);
            buildUrlTarget(existing, "/api/users", "GET");
            stubExisting(existing);

            Policy candidate = buildPolicy(null, "allow-users", Policy.Effect.ALLOW, true);
            buildUrlTarget(candidate, "/api/users", "GET");

            List<PolicyConflictDto> conflicts = analyzer.analyze(candidate);

            assertThat(conflicts).hasSize(1);
            PolicyConflictDto conflict = conflicts.get(0);
            assertThat(conflict.conflictDescription()).contains("msg.policy.conflict.description");
        }
    }
}
