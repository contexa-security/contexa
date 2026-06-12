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
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.authority.AuthorityResolver;
import io.contexa.contexacommon.security.authority.PermissionAuthority;
import io.contexa.contexacommon.security.authority.RoleAuthority;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyImpactReport;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
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
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.GrantedAuthority;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PolicyImpactAnalyzerTest {

    @Mock private UserRepository userRepository;
    @Mock private PolicyRepository policyRepository;
    @Mock private RoleHierarchy roleHierarchy;
    @Mock private AuthorityResolver authorityResolver;

    private PolicyImpactAnalyzer analyzer;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        analyzer = new PolicyImpactAnalyzer(userRepository, policyRepository, roleHierarchy, authorityResolver);
        // RoleHierarchy returns input as-is by default (no hierarchy expansion)
        when(roleHierarchy.getReachableGrantedAuthorities(anyCollection()))
                .thenAnswer(inv -> inv.getArgument(0));
        // AuthorityResolver delegates to buildUser's role setup
        when(authorityResolver.resolveAuthorities(any(Users.class))).thenAnswer(inv -> {
            Users u = inv.getArgument(0);
            Set<GrantedAuthority> auths = new HashSet<>();
            if (u.getUserGroups() != null) {
                u.getUserGroups().forEach(ug -> {
                    if (ug.getGroup() != null && ug.getGroup().getGroupRoles() != null) {
                        ug.getGroup().getGroupRoles().forEach(gr -> {
                            if (gr.getRole() != null && gr.getRole().isEnabled()) {
                                auths.add(new RoleAuthority(gr.getRole()));
                                if (gr.getRole().getRolePermissions() != null) {
                                    gr.getRole().getRolePermissions().forEach(rp -> {
                                        if (rp.getPermission() != null) auths.add(new PermissionAuthority(rp.getPermission()));
                                    });
                                }
                            }
                        });
                    }
                });
            }
            if (u.getUserRoles() != null) {
                u.getUserRoles().forEach(ur -> {
                    if (ur.getRole() != null && ur.getRole().isEnabled()) {
                        auths.add(new RoleAuthority(ur.getRole()));
                    }
                });
            }
            return auths;
        });
    }

    private Policy buildPolicy(Long id, String name, Policy.Effect effect,
                                String targetPath, String httpMethod, String condition) {
        Policy policy = Policy.builder().id(id).name(name).effect(effect).priority(100).isActive(true).build();
        PolicyTarget target = PolicyTarget.builder()
                .policy(policy).targetType("URL").targetIdentifier(targetPath).httpMethod(httpMethod).build();
        policy.getTargets().add(target);
        if (condition != null) {
            PolicyRule rule = PolicyRule.builder().policy(policy).build();
            PolicyCondition cond = PolicyCondition.builder().rule(rule).expression(condition).build();
            rule.setConditions(Set.of(cond));
            policy.getRules().add(rule);
        }
        return policy;
    }

    private Users buildUser(Long id, String username, String roleName) {
        Users user = mock(Users.class);
        when(user.getId()).thenReturn(id);
        when(user.getUsername()).thenReturn(username);

        Role role = mock(Role.class);
        when(role.getId()).thenReturn(id);
        when(role.getRoleName()).thenReturn(roleName);
        when(role.isEnabled()).thenReturn(true);
        when(role.getRolePermissions()).thenReturn(Collections.emptySet());

        GroupRole groupRole = mock(GroupRole.class);
        when(groupRole.getRole()).thenReturn(role);

        Group group = mock(Group.class);
        when(group.getName()).thenReturn("TestGroup");
        when(group.getGroupRoles()).thenReturn(Set.of(groupRole));

        UserGroup userGroup = mock(UserGroup.class);
        when(userGroup.getGroup()).thenReturn(group);

        when(user.getUserGroups()).thenReturn(Set.of(userGroup));
        when(user.getUserRoles()).thenReturn(Collections.emptySet());

        return user;
    }

    // ── 1. 기본 영향 분석 ───────────────────────────────────────

    @Nested
    @DisplayName("기본 영향 분석")
    class BasicImpact {

        @Test
        @DisplayName("타겟이 없는 정책은 영향 없음")
        void noTargetsNoImpact() {
            Policy candidate = Policy.builder().name("empty").effect(Policy.Effect.ALLOW).priority(100).build();
            when(policyRepository.findAllWithDetails()).thenReturn(List.of());

            PolicyImpactReport report = analyzer.analyze(candidate);

            assertThat(report.affectedUserCount()).isEqualTo(0);
            assertThat(report.affectedUsers()).isEmpty();
            assertThat(report.affectedResources()).isEmpty();
        }

        @Test
        @DisplayName("기존 정책 없고 새 ALLOW 정책 추가 시 모든 사용자가 접근 획득")
        void newAllowPolicyGrantsAccess() {
            Policy candidate = buildPolicy(null, "allow-users", Policy.Effect.ALLOW,
                    "/api/users", "GET", "hasAuthority('ROLE_USER')");
            Users user = buildUser(1L, "testuser", "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of());
            when(userRepository.findAll()).thenReturn(List.of(user));

            PolicyImpactReport report = analyzer.analyze(candidate);

            assertThat(report.affectedUserCount()).isEqualTo(1);
            assertThat(report.affectedUsers().get(0).changeType()).isEqualTo("ACCESS_GAINED");
            assertThat(report.accessChangeSummary().gained()).isEqualTo(1);
        }

        @Test
        @DisplayName("기존 ALLOW 정책이 있는 곳에 DENY 추가 시 접근 상실")
        void denyOverridesExistingAllow() {
            Policy existing = buildPolicy(1L, "allow-existing", Policy.Effect.ALLOW,
                    "/api/data", "GET", "hasAuthority('ROLE_USER')");
            Policy candidate = buildPolicy(null, "deny-new", Policy.Effect.DENY,
                    "/api/data", "GET", "hasAuthority('ROLE_USER')");

            Users user = buildUser(1L, "testuser", "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(existing));
            when(userRepository.findAll()).thenReturn(List.of(user));

            PolicyImpactReport report = analyzer.analyze(candidate);

            assertThat(report.affectedUserCount()).isEqualTo(1);
            assertThat(report.affectedUsers().get(0).changeType()).isEqualTo("ACCESS_LOST");
            assertThat(report.accessChangeSummary().lost()).isEqualTo(1);
        }
    }

    // ── 2. 역할 계층 반영 ───────────────────────────────────────

    @Nested
    @DisplayName("역할 계층 반영")
    class RoleHierarchyImpact {

        @Test
        @SuppressWarnings("unchecked")
        @DisplayName("역할 계층에 의해 하위 역할 정책이 상위 역할 사용자에게도 영향")
        void hierarchyExpandsImpact() {
            Policy candidate = buildPolicy(null, "deny-user", Policy.Effect.DENY,
                    "/api/reports", "GET", "hasAuthority('ROLE_USER')");
            Policy existing = buildPolicy(1L, "allow-reports", Policy.Effect.ALLOW,
                    "/api/reports", "GET", "hasAuthority('ROLE_USER')");

            // admin user has ROLE_ADMIN, but hierarchy expands to include ROLE_USER
            Users admin = buildUser(1L, "admin", "ROLE_ADMIN");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(existing));
            when(userRepository.findAll()).thenReturn(List.of(admin));

            // Override authorityResolver to simulate role hierarchy: ROLE_ADMIN -> ROLE_USER
            when(authorityResolver.resolveAuthorities(any(Users.class))).thenAnswer(inv -> {
                Users u = inv.getArgument(0);
                Set<GrantedAuthority> auths = new HashSet<>();
                if (u.getUserGroups() != null) {
                    u.getUserGroups().forEach(ug -> {
                        if (ug.getGroup() != null && ug.getGroup().getGroupRoles() != null) {
                            ug.getGroup().getGroupRoles().forEach(gr -> {
                                if (gr.getRole() != null && gr.getRole().isEnabled()) {
                                    auths.add(new RoleAuthority(gr.getRole()));
                                }
                            });
                        }
                    });
                }
                // Hierarchy: ROLE_ADMIN includes ROLE_USER
                if (auths.stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()))) {
                    Role userRole = mock(Role.class);
                    when(userRole.getRoleName()).thenReturn("ROLE_USER");
                    when(userRole.getId()).thenReturn(99L);
                    auths.add(new RoleAuthority(userRole));
                }
                return auths;
            });

            PolicyImpactReport report = analyzer.analyze(candidate);

            // admin should be affected because hierarchy gives them ROLE_USER
            assertThat(report.affectedUserCount()).isEqualTo(1);
            assertThat(report.affectedUsers().get(0).username()).isEqualTo("admin");
        }
    }

    // ── 3. unchanged 카운트 정확성 ──────────────────────────────

    @Nested
    @DisplayName("unchanged 카운트 정확성")
    class UnchangedCount {

        @Test
        @DisplayName("영향 없는 사용자는 unchanged에 포함됨")
        void unchangedUserCounted() {
            Policy candidate = buildPolicy(null, "deny-admin", Policy.Effect.DENY,
                    "/api/admin", "GET", "hasAuthority('ROLE_ADMIN')");

            Users admin = buildUser(1L, "admin", "ROLE_ADMIN");
            Users user = buildUser(2L, "normaluser", "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of());
            when(userRepository.findAll()).thenReturn(List.of(admin, user));

            PolicyImpactReport report = analyzer.analyze(candidate);

            // Only admin is affected, normaluser is unchanged
            assertThat(report.accessChangeSummary().unchanged()).isEqualTo(1);
        }

        @Test
        @DisplayName("여러 타겟 경로가 있어도 사용자별 unchanged는 1회만 카운트됨")
        void unchangedNotDuplicatedForMultipleTargets() {
            Policy candidate = Policy.builder().name("multi-target").effect(Policy.Effect.DENY).priority(100).build();
            candidate.getTargets().add(PolicyTarget.builder()
                    .policy(candidate).targetType("URL").targetIdentifier("/api/path1").build());
            candidate.getTargets().add(PolicyTarget.builder()
                    .policy(candidate).targetType("URL").targetIdentifier("/api/path2").build());
            PolicyRule rule = PolicyRule.builder().policy(candidate).build();
            rule.setConditions(Set.of(PolicyCondition.builder().rule(rule)
                    .expression("hasAuthority('ROLE_ADMIN')").build()));
            candidate.getRules().add(rule);

            Users user = buildUser(1L, "normaluser", "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of());
            when(userRepository.findAll()).thenReturn(List.of(user));

            PolicyImpactReport report = analyzer.analyze(candidate);

            // normaluser not affected by either path -> unchanged = 1 (not 2)
            assertThat(report.accessChangeSummary().unchanged()).isEqualTo(1);
        }
    }

    // ── 4. 영향받는 리소스 분석 ─────────────────────────────────

    @Nested
    @DisplayName("영향받는 리소스 분석")
    class AffectedResources {

        @Test
        @DisplayName("기존 정책이 동일 타겟을 보호하면 matchedPolicyNames에 포함됨")
        void existingPoliciesListed() {
            Policy existing1 = buildPolicy(1L, "policy-a", Policy.Effect.ALLOW,
                    "/api/users", "GET", "hasAuthority('ROLE_USER')");
            Policy existing2 = buildPolicy(2L, "policy-b", Policy.Effect.DENY,
                    "/api/users", "POST", "hasAuthority('ROLE_ADMIN')");
            Policy candidate = buildPolicy(null, "new-policy", Policy.Effect.ALLOW,
                    "/api/users", "GET", "hasAuthority('ROLE_USER')");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(existing1, existing2));
            when(userRepository.findAll()).thenReturn(List.of());

            PolicyImpactReport report = analyzer.analyze(candidate);

            assertThat(report.affectedResources()).hasSize(1);
            // Both existing policies have /api/users target
            assertThat(report.affectedResources().get(0).matchedPolicyNames())
                    .contains("policy-a", "policy-b");
        }

        @Test
        @DisplayName("기존 정책이 없으면 빈 matchedPolicyNames")
        void noExistingPolicies() {
            Policy candidate = buildPolicy(null, "new", Policy.Effect.ALLOW,
                    "/api/new", "GET", "permitAll");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of());
            when(userRepository.findAll()).thenReturn(List.of());

            PolicyImpactReport report = analyzer.analyze(candidate);

            assertThat(report.affectedResources()).hasSize(1);
            assertThat(report.affectedResources().get(0).matchedPolicyNames()).isEmpty();
        }
    }

    // ── 5. 조건 평가 ────────────────────────────────────────────

    @Nested
    @DisplayName("SpEL 조건 평가")
    class ConditionEvaluation {

        @Test
        @DisplayName("사용자가 조건에 필요한 권한을 갖지 않으면 영향 없음")
        void userWithoutRequiredAuthority() {
            Policy candidate = buildPolicy(null, "admin-only", Policy.Effect.DENY,
                    "/api/admin", "GET", "hasAuthority('ROLE_ADMIN')");
            Users user = buildUser(1L, "normaluser", "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of());
            when(userRepository.findAll()).thenReturn(List.of(user));

            PolicyImpactReport report = analyzer.analyze(candidate);

            assertThat(report.affectedUserCount()).isEqualTo(0);
            assertThat(report.accessChangeSummary().unchanged()).isEqualTo(1);
        }

        @Test
        @DisplayName("permitAll 조건은 모든 사용자에게 매칭됨")
        void permitAllMatchesEveryone() {
            Policy candidate = buildPolicy(null, "public-deny", Policy.Effect.DENY,
                    "/api/public", "GET", "permitAll");
            Users user = buildUser(1L, "anyone", "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of());
            when(userRepository.findAll()).thenReturn(List.of(user));

            PolicyImpactReport report = analyzer.analyze(candidate);

            assertThat(report.affectedUserCount()).isEqualTo(1);
        }

        @Test
        @DisplayName("AI 조건(#ai.)은 영향 분석에서 매칭으로 간주됨")
        void aiConditionAssumedMatch() {
            Policy candidate = buildPolicy(null, "ai-policy", Policy.Effect.ALLOW,
                    "/api/secured", "GET", "#ai.isAllowed()");
            Users user = buildUser(1L, "user", "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of());
            when(userRepository.findAll()).thenReturn(List.of(user));

            PolicyImpactReport report = analyzer.analyze(candidate);

            assertThat(report.affectedUserCount()).isEqualTo(1);
        }

        @Test
        @DisplayName("hasRole('ADMIN')은 hasAuthority('ROLE_ADMIN')과 동일하게 평가됨")
        void hasRoleEquivalent() {
            Policy candidate = buildPolicy(null, "role-deny", Policy.Effect.DENY,
                    "/api/admin", "GET", "hasRole('ADMIN')");
            Users admin = buildUser(1L, "admin", "ROLE_ADMIN");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of());
            when(userRepository.findAll()).thenReturn(List.of(admin));

            PolicyImpactReport report = analyzer.analyze(candidate);

            assertThat(report.affectedUserCount()).isEqualTo(1);
        }
    }

    // ── 6. 엣지 케이스 ──────────────────────────────────────────

    @Nested
    @DisplayName("엣지 케이스")
    class EdgeCases {

        @Test
        @DisplayName("사용자가 없으면 영향 분석 결과도 비어 있음")
        void noUsers() {
            Policy candidate = buildPolicy(null, "policy", Policy.Effect.ALLOW,
                    "/api/test", "GET", "permitAll");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of());
            when(userRepository.findAll()).thenReturn(List.of());

            PolicyImpactReport report = analyzer.analyze(candidate);

            assertThat(report.affectedUserCount()).isEqualTo(0);
            assertThat(report.accessChangeSummary().unchanged()).isEqualTo(0);
        }

        @Test
        @DisplayName("METHOD 타겟은 영향 분석에서 무시됨 (URL만 분석)")
        void methodTargetIgnored() {
            Policy candidate = Policy.builder().name("method-policy").effect(Policy.Effect.ALLOW).priority(100).build();
            candidate.getTargets().add(PolicyTarget.builder()
                    .policy(candidate).targetType("METHOD")
                    .targetIdentifier("com.example.Service.method()").build());

            when(policyRepository.findAllWithDetails()).thenReturn(List.of());

            PolicyImpactReport report = analyzer.analyze(candidate);

            assertThat(report.affectedUserCount()).isEqualTo(0);
            assertThat(report.affectedResources()).isEmpty();
        }
    }
}
