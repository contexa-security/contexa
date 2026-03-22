package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.RolePermission;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class BusinessPolicyServiceImplTest {

    @Mock
    private PolicyRepository policyRepository;

    @Mock
    private RoleService roleService;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PermissionRepository permissionRepository;

    @Mock
    private ConditionTemplateRepository conditionTemplateRepository;

    @Mock
    private PolicyEnrichmentService policyEnrichmentService;

    @Mock
    private CustomDynamicAuthorizationManager authorizationManager;

    @Mock
    private io.contexa.contexacore.autonomous.audit.CentralAuditFacade centralAuditFacade;

    private BusinessPolicyServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new BusinessPolicyServiceImpl(
                policyRepository, roleService, roleRepository,
                permissionRepository, conditionTemplateRepository,
                policyEnrichmentService, authorizationManager, centralAuditFacade);
    }

    @Nested
    @DisplayName("SpEL generation from business rules")
    class SpelGenerationTests {

        @Test
        @DisplayName("Should generate SpEL with role conditions")
        void shouldGenerateSpelWithRoles() {
            BusinessPolicyDto dto = createBasicDto();
            Role adminRole = mock(Role.class);
            when(adminRole.getRoleName()).thenReturn("ROLE_ADMIN");
            Permission perm = createPermission();

            when(roleRepository.findAllById(dto.getRoleIds())).thenReturn(List.of(adminRole));
            when(permissionRepository.findAllById(dto.getPermissionIds())).thenReturn(List.of(perm));
            when(policyRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
            setupRoleServiceMock(dto.getRoleIds());

            Policy result = service.createPolicyFromBusinessRule(dto);

            assertThat(result.getRules()).isNotEmpty();
            PolicyRule rule = result.getRules().iterator().next();
            PolicyCondition condition = rule.getConditions().iterator().next();
            assertThat(condition.getExpression()).contains("hasAuthority('ROLE_ADMIN')");
        }

        @Test
        @DisplayName("Should generate SpEL with permission conditions")
        void shouldGenerateSpelWithPermissions() {
            BusinessPolicyDto dto = createBasicDto();
            Permission perm = createPermission();
            when(perm.getName()).thenReturn("URL_READ_USERS");
            Role role = createRole("ROLE_USER");

            when(roleRepository.findAllById(dto.getRoleIds())).thenReturn(List.of(role));
            when(permissionRepository.findAllById(dto.getPermissionIds())).thenReturn(List.of(perm));
            when(policyRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
            setupRoleServiceMock(dto.getRoleIds());

            Policy result = service.createPolicyFromBusinessRule(dto);

            PolicyRule rule = result.getRules().iterator().next();
            PolicyCondition condition = rule.getConditions().iterator().next();
            assertThat(condition.getExpression()).contains("hasAuthority('URL_READ_USERS')");
        }

        @Test
        @DisplayName("Should generate SpEL with AI action - single ALLOW")
        void shouldGenerateSpelWithSingleAiAction() {
            BusinessPolicyDto dto = createBasicDto();
            dto.setAiActionEnabled(true);
            dto.setAllowedActions(List.of("ALLOW"));
            Role role = createRole("ROLE_USER");
            Permission perm = createPermission();

            when(roleRepository.findAllById(dto.getRoleIds())).thenReturn(List.of(role));
            when(permissionRepository.findAllById(dto.getPermissionIds())).thenReturn(List.of(perm));
            when(policyRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
            setupRoleServiceMock(dto.getRoleIds());

            Policy result = service.createPolicyFromBusinessRule(dto);

            PolicyRule rule = result.getRules().iterator().next();
            PolicyCondition condition = rule.getConditions().iterator().next();
            assertThat(condition.getExpression()).contains("#ai.isAllowed()");
        }

        @Test
        @DisplayName("Should generate SpEL with multiple AI actions using hasActionIn")
        void shouldGenerateSpelWithMultipleAiActions() {
            BusinessPolicyDto dto = createBasicDto();
            dto.setAiActionEnabled(true);
            dto.setAllowedActions(List.of("ALLOW", "CHALLENGE"));
            Role role = createRole("ROLE_USER");
            Permission perm = createPermission();

            when(roleRepository.findAllById(dto.getRoleIds())).thenReturn(List.of(role));
            when(permissionRepository.findAllById(dto.getPermissionIds())).thenReturn(List.of(perm));
            when(policyRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
            setupRoleServiceMock(dto.getRoleIds());

            Policy result = service.createPolicyFromBusinessRule(dto);

            PolicyRule rule = result.getRules().iterator().next();
            PolicyCondition condition = rule.getConditions().iterator().next();
            assertThat(condition.getExpression()).contains("#ai.hasActionIn(");
        }

        @Test
        @DisplayName("Should throw when no roles or permissions provided")
        void shouldThrowWhenNoRolesOrPermissions() {
            BusinessPolicyDto dto = new BusinessPolicyDto();
            dto.setRoleIds(Collections.emptySet());
            dto.setPermissionIds(Set.of(1L));

            assertThatThrownBy(() -> service.createPolicyFromBusinessRule(dto))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("At least one role");
        }
    }

    @Nested
    @DisplayName("SpEL safety validation")
    class SpelSafetyTests {

        @Test
        @DisplayName("Should reject SpEL with T( pattern")
        void shouldRejectTypePattern() {
            BusinessPolicyDto dto = createBasicDto();
            dto.setCustomConditionSpel("T(java.lang.Runtime).getRuntime().exec('cmd')");
            Role role = createRole("ROLE_USER");
            Permission perm = createPermission();

            when(roleRepository.findAllById(dto.getRoleIds())).thenReturn(List.of(role));
            when(permissionRepository.findAllById(dto.getPermissionIds())).thenReturn(List.of(perm));
            setupRoleServiceMock(dto.getRoleIds());

            assertThatThrownBy(() -> service.createPolicyFromBusinessRule(dto))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("dangerous pattern");
        }

        @Test
        @DisplayName("Should reject SpEL with RUNTIME")
        void shouldRejectRuntimePattern() {
            BusinessPolicyDto dto = createBasicDto();
            dto.setCustomConditionSpel("Runtime.getRuntime()");
            Role role = createRole("ROLE_USER");
            Permission perm = createPermission();

            when(roleRepository.findAllById(dto.getRoleIds())).thenReturn(List.of(role));
            when(permissionRepository.findAllById(dto.getPermissionIds())).thenReturn(List.of(perm));
            setupRoleServiceMock(dto.getRoleIds());

            assertThatThrownBy(() -> service.createPolicyFromBusinessRule(dto))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("dangerous pattern");
        }

        @Test
        @DisplayName("Should reject SpEL with EXEC(")
        void shouldRejectExecPattern() {
            BusinessPolicyDto dto = createBasicDto();
            dto.setCustomConditionSpel("exec('malicious')");
            Role role = createRole("ROLE_USER");
            Permission perm = createPermission();

            when(roleRepository.findAllById(dto.getRoleIds())).thenReturn(List.of(role));
            when(permissionRepository.findAllById(dto.getPermissionIds())).thenReturn(List.of(perm));
            setupRoleServiceMock(dto.getRoleIds());

            assertThatThrownBy(() -> service.createPolicyFromBusinessRule(dto))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("dangerous pattern");
        }

        @Test
        @DisplayName("Should reject SpEL with PROCESSBUILDER")
        void shouldRejectProcessBuilder() {
            BusinessPolicyDto dto = createBasicDto();
            dto.setCustomConditionSpel("new ProcessBuilder('cmd')");
            Role role = createRole("ROLE_USER");
            Permission perm = createPermission();

            when(roleRepository.findAllById(dto.getRoleIds())).thenReturn(List.of(role));
            when(permissionRepository.findAllById(dto.getPermissionIds())).thenReturn(List.of(perm));
            setupRoleServiceMock(dto.getRoleIds());

            assertThatThrownBy(() -> service.createPolicyFromBusinessRule(dto))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("dangerous pattern");
        }

        @Test
        @DisplayName("Should reject SpEL with java.lang. reference")
        void shouldRejectJavaLangPattern() {
            BusinessPolicyDto dto = createBasicDto();
            dto.setCustomConditionSpel("java.lang.System.exit(0)");
            Role role = createRole("ROLE_USER");
            Permission perm = createPermission();

            when(roleRepository.findAllById(dto.getRoleIds())).thenReturn(List.of(role));
            when(permissionRepository.findAllById(dto.getPermissionIds())).thenReturn(List.of(perm));
            setupRoleServiceMock(dto.getRoleIds());

            assertThatThrownBy(() -> service.createPolicyFromBusinessRule(dto))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("dangerous pattern");
        }

        @Test
        @DisplayName("Should accept safe SpEL expression")
        void shouldAcceptSafeSpel() {
            BusinessPolicyDto dto = createBasicDto();
            dto.setCustomConditionSpel("#request.remoteAddr == '127.0.0.1'");
            Role role = createRole("ROLE_USER");
            Permission perm = createPermission();

            when(roleRepository.findAllById(dto.getRoleIds())).thenReturn(List.of(role));
            when(permissionRepository.findAllById(dto.getPermissionIds())).thenReturn(List.of(perm));
            when(policyRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
            setupRoleServiceMock(dto.getRoleIds());

            Policy result = service.createPolicyFromBusinessRule(dto);

            PolicyRule rule = result.getRules().iterator().next();
            PolicyCondition condition = rule.getConditions().iterator().next();
            assertThat(condition.getExpression()).contains("#request.remoteAddr == '127.0.0.1'");
        }
    }

    @Nested
    @DisplayName("Role-permission mapping updates")
    class RolePermissionMappingTests {

        @Test
        @DisplayName("Should update role-permission mappings on create")
        void shouldUpdateRolePermissionMappings() {
            BusinessPolicyDto dto = createBasicDto();

            Role role = createRole("ROLE_USER");
            Permission perm = createPermission();
            when(roleService.getRole(1L)).thenReturn(role);
            when(roleRepository.findAllById(dto.getRoleIds())).thenReturn(List.of(role));
            when(permissionRepository.findAllById(dto.getPermissionIds())).thenReturn(List.of(perm));
            when(policyRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            service.createPolicyFromBusinessRule(dto);

            verify(roleService).getRole(1L);
            verify(roleService).updateRole(eq(role), any());
        }
    }

    @Nested
    @DisplayName("authorizationManager.reload() called")
    class ReloadTests {

        @Test
        @DisplayName("Should call reload after create")
        void shouldCallReloadAfterCreate() {
            BusinessPolicyDto dto = createBasicDto();
            Role role = createRole("ROLE_USER");
            Permission perm = createPermission();

            when(roleRepository.findAllById(dto.getRoleIds())).thenReturn(List.of(role));
            when(permissionRepository.findAllById(dto.getPermissionIds())).thenReturn(List.of(perm));
            when(policyRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
            setupRoleServiceMock(dto.getRoleIds());

            service.createPolicyFromBusinessRule(dto);

            verify(authorizationManager).reload();
        }

        @Test
        @DisplayName("Should call reload after update")
        void shouldCallReloadAfterUpdate() {
            BusinessPolicyDto dto = createBasicDto();
            Role role = createRole("ROLE_USER");
            Permission perm = createPermission();

            Policy existingPolicy = Policy.builder().name("existing").effect(Policy.Effect.ALLOW).build();
            existingPolicy.setTargets(new HashSet<>());
            existingPolicy.setRules(new HashSet<>());

            when(policyRepository.findByIdWithDetails(10L)).thenReturn(Optional.of(existingPolicy));
            when(roleRepository.findAllById(dto.getRoleIds())).thenReturn(List.of(role));
            when(permissionRepository.findAllById(dto.getPermissionIds())).thenReturn(List.of(perm));
            when(policyRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
            setupRoleServiceMock(dto.getRoleIds());

            service.updatePolicyFromBusinessRule(10L, dto);

            verify(authorizationManager).reload();
        }
    }

    // -- Helper methods --

    private BusinessPolicyDto createBasicDto() {
        BusinessPolicyDto dto = new BusinessPolicyDto();
        dto.setPolicyName("Test Policy");
        dto.setDescription("Test description");
        dto.setRoleIds(Set.of(1L));
        dto.setPermissionIds(Set.of(100L));
        dto.setEffect(Policy.Effect.ALLOW);
        return dto;
    }

    private Permission createPermission() {
        Permission perm = mock(Permission.class);
        when(perm.getId()).thenReturn(100L);
        when(perm.getName()).thenReturn("URL_READ");
        ManagedResource mr = mock(ManagedResource.class);
        when(mr.getResourceType()).thenReturn(ManagedResource.ResourceType.URL);
        when(mr.getResourceIdentifier()).thenReturn("/api/test");
        when(mr.getHttpMethod()).thenReturn(null);
        when(perm.getManagedResource()).thenReturn(mr);
        return perm;
    }

    private Role createRole(String roleName) {
        Role role = mock(Role.class);
        when(role.getId()).thenReturn(1L);
        when(role.getRoleName()).thenReturn(roleName);
        when(role.getRolePermissions()).thenReturn(new HashSet<>());
        return role;
    }

    private void setupRoleServiceMock(Set<Long> roleIds) {
        for (Long roleId : roleIds) {
            Role role = createRole("ROLE_USER");
            role.setRolePermissions(new HashSet<>());
            when(roleService.getRole(roleId)).thenReturn(role);
        }
    }
}
