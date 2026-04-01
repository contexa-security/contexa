package io.contexa.contexaiam.security.xacml.pap.analysis;

import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyMatrixReport;
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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PolicyMatrixServiceTest {

    @Mock private PolicyRepository policyRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private RoleHierarchy roleHierarchy;

    private PolicyMatrixService service;

    @BeforeEach
    void setUp() {
        service = new PolicyMatrixService(policyRepository, roleRepository, roleHierarchy);
        when(roleHierarchy.getReachableGrantedAuthorities(anyCollection()))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    private Policy buildPolicy(Long id, String name, Policy.Effect effect,
                                String path, String condition) {
        Policy policy = Policy.builder().id(id).name(name).effect(effect).priority(100).isActive(true).build();
        PolicyTarget target = PolicyTarget.builder()
                .policy(policy).targetType("URL").targetIdentifier(path).httpMethod("GET").build();
        policy.getTargets().add(target);
        PolicyRule rule = PolicyRule.builder().policy(policy).build();
        PolicyCondition cond = PolicyCondition.builder().rule(rule).expression(condition).build();
        rule.setConditions(Set.of(cond));
        policy.getRules().add(rule);
        return policy;
    }

    private Role buildRole(Long id, String name) {
        return Role.builder().id(id).roleName(name).enabled(true).build();
    }

    @Nested
    @DisplayName("기본 매트릭스 생성")
    class BasicMatrix {

        @Test
        @DisplayName("정책과 역할이 있으면 매트릭스 셀이 생성됨")
        void matrixWithPoliciesAndRoles() {
            Policy policy = buildPolicy(1L, "allow-users", Policy.Effect.ALLOW,
                    "/api/users", "hasAuthority('ROLE_USER')");
            Role role = buildRole(1L, "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(policy));
            when(roleRepository.findAll()).thenReturn(List.of(role));

            PolicyMatrixReport report = service.generateMatrix(null, null);

            assertThat(report.resources()).hasSize(1);
            assertThat(report.roles()).containsExactly("ROLE_USER");
            assertThat(report.cells()).hasSize(1);
            assertThat(report.cells().getFirst().getFirst().access()).isEqualTo("ALLOW");
            assertThat(report.cells().getFirst().getFirst().inherited()).isFalse();
        }

        @Test
        @DisplayName("정책이 없으면 빈 매트릭스")
        void emptyMatrix() {
            when(policyRepository.findAllWithDetails()).thenReturn(List.of());
            when(roleRepository.findAll()).thenReturn(List.of(buildRole(1L, "ROLE_USER")));

            PolicyMatrixReport report = service.generateMatrix(null, null);

            assertThat(report.resources()).isEmpty();
            assertThat(report.cells()).isEmpty();
        }
    }

    @Nested
    @DisplayName("역할 계층 상속 반영")
    class HierarchyInheritance {

        @Test
        @SuppressWarnings("unchecked")
        @DisplayName("ROLE_USER 정책이 ROLE_ADMIN에게 상속으로 표시됨")
        void inheritedAccess() {
            Policy policy = buildPolicy(1L, "allow-users", Policy.Effect.ALLOW,
                    "/api/users", "hasAuthority('ROLE_USER')");
            Role admin = buildRole(1L, "ROLE_ADMIN");
            Role user = buildRole(2L, "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(policy));
            when(roleRepository.findAll()).thenReturn(List.of(admin, user));

            // ROLE_ADMIN inherits ROLE_USER
            when(roleHierarchy.getReachableGrantedAuthorities(anyCollection()))
                    .thenAnswer(inv -> {
                        Collection<GrantedAuthority> input = (Collection<GrantedAuthority>) inv.getArgument(0);
                        if (input.stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()))) {
                            return List.of(new SimpleGrantedAuthority("ROLE_ADMIN"),
                                    new SimpleGrantedAuthority("ROLE_USER"));
                        }
                        return input;
                    });

            PolicyMatrixReport report = service.generateMatrix(null, null);

            // ROLE_ADMIN cell should show inherited=true
            assertThat(report.cells().getFirst().get(0).access()).isEqualTo("ALLOW");
            assertThat(report.cells().getFirst().get(0).inherited()).isTrue();
            // ROLE_USER cell should show inherited=false (direct)
            assertThat(report.cells().getFirst().get(1).access()).isEqualTo("ALLOW");
            assertThat(report.cells().getFirst().get(1).inherited()).isFalse();
        }
    }

    @Nested
    @DisplayName("충돌 감지")
    class ConflictDetection {

        @Test
        @DisplayName("같은 리소스에 ALLOW와 DENY가 있으면 충돌 셀이 표시됨")
        void conflictCellDetected() {
            Policy allow = buildPolicy(1L, "allow", Policy.Effect.ALLOW,
                    "/api/data", "hasAuthority('ROLE_USER')");
            Policy deny = buildPolicy(2L, "deny", Policy.Effect.DENY,
                    "/api/data", "hasAuthority('ROLE_USER')");
            Role role = buildRole(1L, "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(allow, deny));
            when(roleRepository.findAll()).thenReturn(List.of(role));

            PolicyMatrixReport report = service.generateMatrix(null, null);

            assertThat(report.conflictCells()).isNotEmpty();
        }
    }

    @Nested
    @DisplayName("필터링")
    class Filtering {

        @Test
        @DisplayName("리소스 필터 적용 시 매칭되는 리소스만 표시됨")
        void resourceFilter() {
            Policy p1 = buildPolicy(1L, "p1", Policy.Effect.ALLOW, "/api/users", "hasAuthority('ROLE_USER')");
            Policy p2 = buildPolicy(2L, "p2", Policy.Effect.ALLOW, "/api/orders", "hasAuthority('ROLE_USER')");
            Role role = buildRole(1L, "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(p1, p2));
            when(roleRepository.findAll()).thenReturn(List.of(role));

            PolicyMatrixReport report = service.generateMatrix("users", null);

            assertThat(report.resources()).hasSize(1);
            assertThat(report.resources().getFirst().identifier()).contains("users");
        }

        @Test
        @DisplayName("역할 필터 적용 시 매칭되는 역할만 표시됨")
        void roleFilter() {
            Policy policy = buildPolicy(1L, "p1", Policy.Effect.ALLOW, "/api/users", "hasAuthority('ROLE_USER')");
            Role admin = buildRole(1L, "ROLE_ADMIN");
            Role user = buildRole(2L, "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(policy));
            when(roleRepository.findAll()).thenReturn(List.of(admin, user));

            PolicyMatrixReport report = service.generateMatrix(null, "ADMIN");

            assertThat(report.roles()).hasSize(1);
            assertThat(report.roles().getFirst()).isEqualTo("ROLE_ADMIN");
        }
    }

    @Nested
    @DisplayName("엣지 케이스")
    class EdgeCases {

        @Test
        @DisplayName("역할이 정책 조건과 매칭되지 않으면 null 셀")
        void unmatchedRoleNullCell() {
            Policy policy = buildPolicy(1L, "admin-only", Policy.Effect.ALLOW,
                    "/api/admin", "hasAuthority('ROLE_ADMIN')");
            Role user = buildRole(1L, "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(policy));
            when(roleRepository.findAll()).thenReturn(List.of(user));

            PolicyMatrixReport report = service.generateMatrix(null, null);

            assertThat(report.cells().getFirst().getFirst()).isNull();
        }

        @Test
        @DisplayName("permitAll 조건은 모든 역할에 매칭됨")
        void permitAllMatchesAllRoles() {
            Policy policy = buildPolicy(1L, "public", Policy.Effect.ALLOW,
                    "/api/public", "permitAll");
            Role role = buildRole(1L, "ROLE_USER");

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(policy));
            when(roleRepository.findAll()).thenReturn(List.of(role));

            PolicyMatrixReport report = service.generateMatrix(null, null);

            assertThat(report.cells().getFirst().getFirst()).isNotNull();
            assertThat(report.cells().getFirst().getFirst().access()).isEqualTo("ALLOW");
        }
    }
}
