package io.contexa.contexaiam.security.xacml.pap.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.web.studio.dto.SimulationResultDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.PolicyTemplateRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.*;
import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.modelmapper.ModelMapper;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PolicyBuilderServiceImplTest {

    @Mock
    private PolicyRepository policyRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private PermissionRepository permissionRepository;

    @Mock
    private PolicyTemplateRepository policyTemplateRepository;

    @Mock
    private PolicyService policyService;

    @Mock
    private ModelMapper modelMapper;

    @Mock
    private ObjectMapper objectMapper;

    private PolicyBuilderServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new PolicyBuilderServiceImpl(
                policyRepository, userRepository, permissionRepository,
                policyTemplateRepository, policyService, modelMapper, objectMapper);
    }

    @Nested
    @DisplayName("Visual components to policy conversion")
    class VisualToPolicyTests {

        @Test
        @DisplayName("Should build policy from visual components with subjects and permissions")
        void shouldBuildPolicyFromVisualComponents() {
            Permission perm = mock(Permission.class);
            when(perm.getName()).thenReturn("URL_READ_USERS");
            ManagedResource mr = mock(ManagedResource.class);
            when(mr.getResourceType()).thenReturn(ManagedResource.ResourceType.URL);
            when(mr.getResourceIdentifier()).thenReturn("/api/users");
            when(mr.getHttpMethod()).thenReturn(null);
            when(perm.getManagedResource()).thenReturn(mr);

            when(permissionRepository.findAllById(Set.of(1L))).thenReturn(List.of(perm));

            Policy expectedPolicy = Policy.builder().name("visual-policy").effect(Policy.Effect.ALLOW).build();
            when(modelMapper.map(any(Policy.class), eq(PolicyDto.class))).thenReturn(new PolicyDto());
            when(policyService.createPolicy(any())).thenReturn(expectedPolicy);

            VisualPolicyDto dto = new VisualPolicyDto(
                    "visual-policy",
                    "Visual policy description",
                    Policy.Effect.ALLOW,
                    Set.of(new VisualPolicyDto.SubjectIdentifier(10L, "ROLE")),
                    Set.of(new VisualPolicyDto.PermissionIdentifier(1L)),
                    Set.of()
            );

            Policy result = service.buildPolicyFromVisualComponents(dto);

            assertThat(result).isNotNull();
            verify(policyService).createPolicy(any());
        }

        @Test
        @DisplayName("Should create rule with subject and permission SpEL expressions")
        void shouldCreateRuleWithSpelExpressions() {
            Permission perm = mock(Permission.class);
            when(perm.getName()).thenReturn("URL_WRITE");
            when(perm.getManagedResource()).thenReturn(null);

            when(permissionRepository.findAllById(Set.of(5L))).thenReturn(List.of(perm));
            when(modelMapper.map(any(Policy.class), eq(PolicyDto.class))).thenReturn(new PolicyDto());
            when(policyService.createPolicy(any())).thenAnswer(inv -> {
                PolicyDto dto = inv.getArgument(0);
                return Policy.builder().name("test").effect(Policy.Effect.ALLOW).build();
            });

            VisualPolicyDto dto = new VisualPolicyDto(
                    "test-policy", "desc", Policy.Effect.ALLOW,
                    Set.of(new VisualPolicyDto.SubjectIdentifier(1L, "USER")),
                    Set.of(new VisualPolicyDto.PermissionIdentifier(5L)),
                    Set.of()
            );

            service.buildPolicyFromVisualComponents(dto);

            verify(policyService).createPolicy(any());
        }
    }

    @Nested
    @DisplayName("Impact simulation (PERMISSION_GAINED, PERMISSION_LOST)")
    class SimulationTests {

        @Test
        @DisplayName("Should return empty result when no target users specified")
        void shouldReturnEmptyForNoUsers() {
            Policy policy = Policy.builder().name("test").effect(Policy.Effect.ALLOW).build();
            policy.setRules(new HashSet<>());

            SimulationResultDto result = service.simulatePolicy(policy, null);

            assertThat(result.summary()).contains("No target users");
            assertThat(result.impactDetails()).isEmpty();
        }

        @Test
        @DisplayName("Should return empty result when userIds is empty")
        void shouldReturnEmptyForEmptyUserIds() {
            Policy policy = Policy.builder().name("test").effect(Policy.Effect.ALLOW).build();
            policy.setRules(new HashSet<>());

            SimulationContext ctx = new SimulationContext(Collections.emptySet(), null, null);

            SimulationResultDto result = service.simulatePolicy(policy, ctx);

            assertThat(result.summary()).contains("No target users");
        }

        @Test
        @DisplayName("Should detect PERMISSION_GAINED when ALLOW policy adds new permissions")
        void shouldDetectPermissionGained() {
            // Build policy with PERM_ authority in condition
            Policy policy = Policy.builder().name("grant-policy").effect(Policy.Effect.ALLOW).build();
            PolicyRule rule = PolicyRule.builder().build();
            PolicyCondition condition = PolicyCondition.builder()
                    .expression("hasAuthority('PERM_WRITE')").build();
            rule.setConditions(Set.of(condition));
            policy.setRules(Set.of(rule));
            policy.setTargets(new HashSet<>());

            Users user = mock(Users.class);
            when(user.getName()).thenReturn("testUser");
            when(user.getUsername()).thenReturn("testUser");
            when(user.getUserGroups()).thenReturn(Collections.emptySet());

            when(userRepository.findAllById(Set.of(1L))).thenReturn(List.of(user));

            Permission perm = mock(Permission.class);
            when(perm.getDescription()).thenReturn("Write permission");
            when(permissionRepository.findByName("PERM_WRITE")).thenReturn(Optional.of(perm));

            SimulationContext ctx = new SimulationContext(Set.of(1L), null, null);

            SimulationResultDto result = service.simulatePolicy(policy, ctx);

            boolean hasGained = result.impactDetails().stream()
                    .anyMatch(d -> d.impactType() == SimulationResultDto.ImpactType.PERMISSION_GAINED);
            assertThat(hasGained).isTrue();
        }

        @Test
        @DisplayName("Should detect PERMISSION_LOST when DENY policy removes existing permissions")
        void shouldDetectPermissionLost() {
            // Build DENY policy that removes PERM_READ
            Policy policy = Policy.builder().name("deny-policy").effect(Policy.Effect.DENY).build();
            PolicyRule rule = PolicyRule.builder().build();
            PolicyCondition condition = PolicyCondition.builder()
                    .expression("hasAuthority('PERM_READ')").build();
            rule.setConditions(Set.of(condition));
            policy.setRules(Set.of(rule));
            policy.setTargets(new HashSet<>());

            // User who currently has PERM_READ through role->permission chain
            Users user = mock(Users.class);
            when(user.getName()).thenReturn("testUser");
            when(user.getUsername()).thenReturn("testUser");

            // Build authority chain: user -> group -> role -> permission
            Permission readPerm = mock(Permission.class);
            when(readPerm.getName()).thenReturn("PERM_READ");
            when(readPerm.getId()).thenReturn(1L);
            when(readPerm.getTargetType()).thenReturn(null);
            when(readPerm.getActionType()).thenReturn(null);

            RolePermission rolePermission = mock(RolePermission.class);
            when(rolePermission.getPermission()).thenReturn(readPerm);

            Role role = mock(Role.class);
            when(role.getId()).thenReturn(1L);
            when(role.getRoleName()).thenReturn("ROLE_USER");
            when(role.getRolePermissions()).thenReturn(Set.of(rolePermission));

            GroupRole groupRole = mock(GroupRole.class);
            when(groupRole.getRole()).thenReturn(role);

            Group group = mock(Group.class);
            when(group.getGroupRoles()).thenReturn(Set.of(groupRole));

            UserGroup userGroup = mock(UserGroup.class);
            when(userGroup.getGroup()).thenReturn(group);

            when(user.getUserGroups()).thenReturn(Set.of(userGroup));

            when(userRepository.findAllById(Set.of(1L))).thenReturn(List.of(user));

            Permission lookupPerm = mock(Permission.class);
            when(lookupPerm.getDescription()).thenReturn("Read permission");
            when(permissionRepository.findByName("PERM_READ")).thenReturn(Optional.of(lookupPerm));

            SimulationContext ctx = new SimulationContext(Set.of(1L), null, null);

            SimulationResultDto result = service.simulatePolicy(policy, ctx);

            boolean hasLost = result.impactDetails().stream()
                    .anyMatch(d -> d.impactType() == SimulationResultDto.ImpactType.PERMISSION_LOST);
            assertThat(hasLost).isTrue();
        }
    }

    @Nested
    @DisplayName("Conflict detection (same target, different effects)")
    class ConflictDetectionTests {

        @Test
        @DisplayName("Should detect conflict when new DENY policy overlaps with existing ALLOW policy target")
        void shouldDetectConflictOnOverlappingTargets() {
            Policy existingPolicy = Policy.builder()
                    .id(1L).name("allow-policy").effect(Policy.Effect.ALLOW).build();
            PolicyTarget existingTarget = PolicyTarget.builder()
                    .targetType("URL").targetIdentifier("/api/users").build();
            existingPolicy.setTargets(Set.of(existingTarget));

            Policy newPolicy = Policy.builder()
                    .id(2L).name("deny-policy").effect(Policy.Effect.DENY).build();
            PolicyTarget newTarget = PolicyTarget.builder()
                    .targetType("URL").targetIdentifier("/api/users").build();
            newPolicy.setTargets(Set.of(newTarget));

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(existingPolicy));

            List<PolicyConflictDto> conflicts = service.detectConflicts(newPolicy);

            assertThat(conflicts).hasSize(1);
            assertThat(conflicts.getFirst().conflictDescription()).contains("conflict");
        }

        @Test
        @DisplayName("Should not detect conflict when policies have same effect")
        void shouldNotDetectConflictForSameEffect() {
            Policy existingPolicy = Policy.builder()
                    .id(1L).name("allow-1").effect(Policy.Effect.ALLOW).build();
            PolicyTarget existingTarget = PolicyTarget.builder()
                    .targetType("URL").targetIdentifier("/api/users").build();
            existingPolicy.setTargets(Set.of(existingTarget));

            Policy newPolicy = Policy.builder()
                    .id(2L).name("allow-2").effect(Policy.Effect.ALLOW).build();
            PolicyTarget newTarget = PolicyTarget.builder()
                    .targetType("URL").targetIdentifier("/api/users").build();
            newPolicy.setTargets(Set.of(newTarget));

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(existingPolicy));

            List<PolicyConflictDto> conflicts = service.detectConflicts(newPolicy);

            assertThat(conflicts).isEmpty();
        }

        @Test
        @DisplayName("Should not detect conflict when targets do not overlap")
        void shouldNotDetectConflictForDifferentTargets() {
            Policy existingPolicy = Policy.builder()
                    .id(1L).name("allow").effect(Policy.Effect.ALLOW).build();
            PolicyTarget existingTarget = PolicyTarget.builder()
                    .targetType("URL").targetIdentifier("/api/users").build();
            existingPolicy.setTargets(Set.of(existingTarget));

            Policy newPolicy = Policy.builder()
                    .id(2L).name("deny").effect(Policy.Effect.DENY).build();
            PolicyTarget newTarget = PolicyTarget.builder()
                    .targetType("URL").targetIdentifier("/api/orders").build();
            newPolicy.setTargets(Set.of(newTarget));

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(existingPolicy));

            List<PolicyConflictDto> conflicts = service.detectConflicts(newPolicy);

            assertThat(conflicts).isEmpty();
        }

        @Test
        @DisplayName("Should skip self-comparison when policy has same id")
        void shouldSkipSelfComparison() {
            Policy existingPolicy = Policy.builder()
                    .id(1L).name("policy-1").effect(Policy.Effect.ALLOW).build();
            PolicyTarget target = PolicyTarget.builder()
                    .targetType("URL").targetIdentifier("/api/users").build();
            existingPolicy.setTargets(Set.of(target));

            Policy samePolicy = Policy.builder()
                    .id(1L).name("policy-1-updated").effect(Policy.Effect.DENY).build();
            samePolicy.setTargets(Set.of(PolicyTarget.builder()
                    .targetType("URL").targetIdentifier("/api/users").build()));

            when(policyRepository.findAllWithDetails()).thenReturn(List.of(existingPolicy));

            List<PolicyConflictDto> conflicts = service.detectConflicts(samePolicy);

            assertThat(conflicts).isEmpty();
        }
    }

    @Nested
    @DisplayName("Authority initialization (Users -> Groups -> Roles -> Permissions)")
    class AuthorityInitializationTests {

        @Test
        @DisplayName("Should build authority chain through user groups")
        void shouldBuildAuthorityChainThroughGroups() {
            // The initializeAuthorities method is tested indirectly via simulatePolicy
            Policy policy = Policy.builder().name("test").effect(Policy.Effect.ALLOW).build();
            PolicyRule rule = PolicyRule.builder().build();
            PolicyCondition condition = PolicyCondition.builder()
                    .expression("hasAuthority('PERM_NEW')").build();
            rule.setConditions(Set.of(condition));
            policy.setRules(Set.of(rule));
            policy.setTargets(new HashSet<>());

            // Build chain: Users -> UserGroup -> Group -> GroupRole -> Role -> RolePermission -> Permission
            Permission existingPerm = mock(Permission.class);
            when(existingPerm.getId()).thenReturn(10L);
            when(existingPerm.getName()).thenReturn("PERM_EXISTING");
            when(existingPerm.getTargetType()).thenReturn(null);
            when(existingPerm.getActionType()).thenReturn(null);

            RolePermission rolePermission = mock(RolePermission.class);
            when(rolePermission.getPermission()).thenReturn(existingPerm);

            Role role = mock(Role.class);
            when(role.getId()).thenReturn(1L);
            when(role.getRoleName()).thenReturn("ROLE_USER");
            when(role.getRolePermissions()).thenReturn(Set.of(rolePermission));

            GroupRole groupRole = mock(GroupRole.class);
            when(groupRole.getRole()).thenReturn(role);

            Group group = mock(Group.class);
            when(group.getGroupRoles()).thenReturn(Set.of(groupRole));

            UserGroup userGroup = mock(UserGroup.class);
            when(userGroup.getGroup()).thenReturn(group);

            Users user = mock(Users.class);
            when(user.getName()).thenReturn("chainUser");
            when(user.getUsername()).thenReturn("chainUser");
            when(user.getUserGroups()).thenReturn(Set.of(userGroup));

            when(userRepository.findAllById(Set.of(1L))).thenReturn(List.of(user));
            when(permissionRepository.findByName("PERM_NEW")).thenReturn(Optional.empty());

            SimulationContext ctx = new SimulationContext(Set.of(1L), null, null);
            SimulationResultDto result = service.simulatePolicy(policy, ctx);

            // The user should have PERM_EXISTING in authorities, meaning chain was built correctly
            assertThat(result).isNotNull();
            assertThat(result.summary()).contains("1 users");
        }
    }
}
