package io.contexa.contexaiam.security.xacml.pap.analysis;

import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationTestCase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PolicySimulatorTest {

    @Mock private UserRepository userRepository;
    @Mock private PolicyRepository policyRepository;
    @Mock private RoleHierarchy roleHierarchy;

    private PolicySimulator simulator;

    @BeforeEach
    void setUp() {
        simulator = new PolicySimulator(userRepository, policyRepository, roleHierarchy);
        when(roleHierarchy.getReachableGrantedAuthorities(anyCollection()))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    private Policy buildPolicy(Long id, String name, Policy.Effect effect,
                                String path, String condition) {
        Policy policy = Policy.builder().id(id).name(name).effect(effect).priority(100).isActive(true).build();
        PolicyTarget target = PolicyTarget.builder()
                .policy(policy).targetType("URL").targetIdentifier(path).build();
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
        when(group.getGroupRoles()).thenReturn(Set.of(groupRole));
        UserGroup userGroup = mock(UserGroup.class);
        when(userGroup.getGroup()).thenReturn(group);

        when(user.getUserGroups()).thenReturn(Set.of(userGroup));
        when(user.getUserRoles()).thenReturn(Collections.emptySet());
        return user;
    }

    // ── 1. 기본 시뮬레이션 ──────────────────────────────────────

    @Nested
    @DisplayName("기본 시뮬레이션")
    class BasicSimulation {

        @Test
        @DisplayName("후보 정책 없이 현재 정책만 평가")
        void simulateCurrentPoliciesOnly() {
            Policy existing = buildPolicy(1L, "allow-users", Policy.Effect.ALLOW,
                    "/api/users", "hasAuthority('ROLE_USER')");
            Users user = buildUser(1L, "testuser", "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(existing));
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));

            SimulationReport report = simulator.simulate(null,
                    List.of(new SimulationTestCase(1L, "/api/users", "GET")));

            assertThat(report.results()).hasSize(1);
            assertThat(report.results().getFirst().currentResult().decision()).isEqualTo("ALLOW");
            assertThat(report.results().getFirst().changed()).isFalse();
            assertThat(report.summary().unchanged()).isEqualTo(1);
        }

        @Test
        @DisplayName("후보 DENY 정책 추가 시 ALLOW -> DENY 변경 감지")
        void candidateDenyChangesAllowToDeny() {
            Policy existing = buildPolicy(1L, "allow-users", Policy.Effect.ALLOW,
                    "/api/data", "hasAuthority('ROLE_USER')");
            Policy candidate = buildPolicy(null, "deny-data", Policy.Effect.DENY,
                    "/api/data", "hasAuthority('ROLE_USER')");
            Users user = buildUser(1L, "testuser", "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(existing));
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));

            SimulationReport report = simulator.simulate(candidate,
                    List.of(new SimulationTestCase(1L, "/api/data", "GET")));

            assertThat(report.results()).hasSize(1);
            assertThat(report.results().getFirst().changed()).isTrue();
            assertThat(report.results().getFirst().changeType()).isEqualTo("ALLOW_TO_DENY");
            assertThat(report.summary().allowToDeny()).isEqualTo(1);
        }

        @Test
        @DisplayName("후보 ALLOW 정책 추가 시 NONE -> ALLOW 변경 감지")
        void candidateAllowGrantsAccess() {
            Policy candidate = buildPolicy(null, "allow-new", Policy.Effect.ALLOW,
                    "/api/new", "hasAuthority('ROLE_USER')");
            Users user = buildUser(1L, "testuser", "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of());
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));

            SimulationReport report = simulator.simulate(candidate,
                    List.of(new SimulationTestCase(1L, "/api/new", "GET")));

            assertThat(report.results().getFirst().changed()).isTrue();
            assertThat(report.results().getFirst().changeType()).isEqualTo("DENY_TO_ALLOW");
            assertThat(report.summary().denyToAllow()).isEqualTo(1);
        }
    }

    // ── 2. 여러 테스트 케이스 ───────────────────────────────────

    @Nested
    @DisplayName("여러 테스트 케이스")
    class MultipleTestCases {

        @Test
        @DisplayName("여러 사용자/경로 조합의 시뮬레이션 결과가 각각 반환됨")
        void multipleTestCases() {
            Policy existing = buildPolicy(1L, "allow-users", Policy.Effect.ALLOW,
                    "/api/users", "hasAuthority('ROLE_USER')");
            Policy candidate = buildPolicy(null, "deny-admin", Policy.Effect.DENY,
                    "/api/admin", "hasAuthority('ROLE_ADMIN')");
            Users user = buildUser(1L, "user", "ROLE_USER");
            Users admin = buildUser(2L, "admin", "ROLE_ADMIN");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(existing));
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));
            when(userRepository.findByIdWithGroupsRolesAndPermissions(2L)).thenReturn(Optional.of(admin));

            SimulationReport report = simulator.simulate(candidate, List.of(
                    new SimulationTestCase(1L, "/api/users", "GET"),
                    new SimulationTestCase(2L, "/api/admin", "POST")));

            assertThat(report.results()).hasSize(2);
        }
    }

    // ── 3. 사용자 미존재 ────────────────────────────────────────

    @Nested
    @DisplayName("엣지 케이스")
    class EdgeCases {

        @Test
        @DisplayName("존재하지 않는 사용자 ID는 결과에서 제외됨")
        void nonExistentUserSkipped() {
            when(policyRepository.findAllWithDetails()).thenReturn(List.of());
            when(userRepository.findByIdWithGroupsRolesAndPermissions(999L)).thenReturn(Optional.empty());

            SimulationReport report = simulator.simulate(null,
                    List.of(new SimulationTestCase(999L, "/api/test", "GET")));

            assertThat(report.results()).isEmpty();
        }

        @Test
        @DisplayName("빈 테스트 케이스 목록이면 빈 결과")
        void emptyTestCases() {
            when(policyRepository.findAllWithDetails()).thenReturn(List.of());

            SimulationReport report = simulator.simulate(null, List.of());

            assertThat(report.results()).isEmpty();
            assertThat(report.summary().unchanged()).isEqualTo(0);
        }

        @Test
        @DisplayName("결과에 사용자의 권한 목록이 포함됨")
        void resultIncludesUserAuthorities() {
            Policy existing = buildPolicy(1L, "allow", Policy.Effect.ALLOW,
                    "/api/test", "hasAuthority('ROLE_USER')");
            Users user = buildUser(1L, "testuser", "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(existing));
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));

            SimulationReport report = simulator.simulate(null,
                    List.of(new SimulationTestCase(1L, "/api/test", "GET")));

            assertThat(report.results().getFirst().currentResult().userAuthorities())
                    .contains("ROLE_USER");
        }

        @Test
        @DisplayName("매칭된 정책 이름과 expression이 결과에 포함됨")
        void resultIncludesPolicyDetails() {
            Policy existing = buildPolicy(1L, "my-policy", Policy.Effect.ALLOW,
                    "/api/test", "hasAuthority('ROLE_USER')");
            Users user = buildUser(1L, "testuser", "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(existing));
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));

            SimulationReport report = simulator.simulate(null,
                    List.of(new SimulationTestCase(1L, "/api/test", "GET")));

            assertThat(report.results().getFirst().currentResult().matchedPolicyName())
                    .isEqualTo("my-policy");
            assertThat(report.results().getFirst().currentResult().matchedExpression())
                    .contains("hasAuthority('ROLE_USER')");
        }
    }
}
