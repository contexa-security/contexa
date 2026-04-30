package io.contexa.contexaiam.admin.web.auth.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.web.auth.dto.AffectedPolicyDtos.AffectedPoliciesResponse;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.metadata.service.FunctionCatalogService;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.repository.PermissionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.modelmapper.ModelMapper;
import org.springframework.context.MessageSource;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("PermissionController")
class PermissionControllerTest {

    @Mock
    private PermissionService permissionService;

    @Mock
    private ModelMapper modelMapper;

    @Mock
    private FunctionCatalogService functionCatalogService;

    @Mock
    private PermissionRepository permissionRepository;

    @Mock
    private PolicyRepository policyRepository;

    @Mock
    private MessageSource messageSource;

    @InjectMocks
    private PermissionController controller;

    @BeforeEach
    void setUpMessageSource() {
        when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
                .thenAnswer(inv -> {
                    String key = inv.getArgument(0);
                    Object[] args = inv.getArgument(1);
                    if (args != null && args.length > 0) {
                        return key + " " + Arrays.stream(args)
                                .map(String::valueOf).collect(Collectors.joining(" "));
                    }
                    return key;
                });
    }

    @Nested
    @DisplayName("getPermissions")
    class GetPermissions {

        @Test
        @DisplayName("should return permissions view with mapped list")
        void success() {
            Model model = new ConcurrentModel();
            Pageable pageable = PageRequest.of(0, 15);
            Permission permission = new Permission();
            permission.setName("READ_USER");
            PermissionDto dto = PermissionDto.builder().name("READ_USER").build();

            when(permissionRepository.findAll(pageable)).thenReturn(new PageImpl<>(List.of(permission)));
            when(modelMapper.map(permission, PermissionDto.class)).thenReturn(dto);

            String view = controller.getPermissions(null, pageable, model);

            assertThat(view).isEqualTo("admin/permissions");
            assertThat(model.getAttribute("permissions")).isNotNull();
        }

        @Test
        @DisplayName("should map managed resource fields when present")
        void withManagedResource() {
            Model model = new ConcurrentModel();
            Pageable pageable = PageRequest.of(0, 15);
            ManagedResource resource = new ManagedResource();
            resource.setId(10L);
            resource.setResourceIdentifier("api/users");
            Permission permission = new Permission();
            permission.setManagedResource(resource);

            PermissionDto dto = PermissionDto.builder().build();
            when(permissionRepository.findAll(pageable)).thenReturn(new PageImpl<>(List.of(permission)));
            when(modelMapper.map(permission, PermissionDto.class)).thenReturn(dto);

            String view = controller.getPermissions(null, pageable, model);

            assertThat(view).isEqualTo("admin/permissions");
            assertThat(dto.getLinkedResourceId()).isEqualTo(10L);
            assertThat(dto.getLinkedResourceIdentifier()).isEqualTo("api/users");
        }
    }

    @Nested
    @DisplayName("registerPermissionForm")
    class RegisterPermissionForm {

        @Test
        @DisplayName("should return permission form with empty dto")
        void success() {
            Model model = new ConcurrentModel();

            String view = controller.registerPermissionForm(model);

            assertThat(view).isEqualTo("admin/permissiondetails");
            assertThat(model.getAttribute("permission")).isInstanceOf(PermissionDto.class);
        }
    }

    @Nested
    @DisplayName("createPermission")
    class CreatePermission {

        @Test
        @DisplayName("should redirect with success message on creation")
        void success() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            PermissionDto permDto = PermissionDto.builder().name("WRITE_USER").build();
            Permission permission = new Permission();
            permission.setName("WRITE_USER");
            when(modelMapper.map(permDto, Permission.class)).thenReturn(permission);

            String view = controller.createPermission(permDto, ra);

            assertThat(view).isEqualTo("redirect:/admin/permissions");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("WRITE_USER");
            verify(permissionService).createPermission(permission);
        }
    }

    @Nested
    @DisplayName("permissionDetails")
    class PermissionDetails {

        @Test
        @DisplayName("should return permission details for valid id")
        void success() {
            Model model = new ConcurrentModel();
            Permission permission = new Permission();
            permission.setId(1L);
            PermissionDto dto = PermissionDto.builder().id(1L).build();

            when(permissionService.getPermission(1L)).thenReturn(Optional.of(permission));
            when(modelMapper.map(permission, PermissionDto.class)).thenReturn(dto);

            String view = controller.permissionDetails(1L, model);

            assertThat(view).isEqualTo("admin/permissiondetails");
            assertThat(model.getAttribute("permission")).isEqualTo(dto);
        }

        @Test
        @DisplayName("should throw exception for invalid id")
        void invalidId() {
            Model model = new ConcurrentModel();
            when(permissionService.getPermission(999L)).thenReturn(Optional.empty());

            assertThrows(IllegalArgumentException.class,
                    () -> controller.permissionDetails(999L, model));
        }
    }

    @Nested
    @DisplayName("updatePermission")
    class UpdatePermission {

        @Test
        @DisplayName("should redirect with success message on update")
        void success() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            PermissionDto permDto = PermissionDto.builder().name("UPDATED").build();
            Permission updated = new Permission();
            updated.setName("UPDATED");
            when(permissionService.updatePermission(eq(1L), any())).thenReturn(updated);

            String view = controller.updatePermission(1L, permDto, ra);

            assertThat(view).isEqualTo("redirect:/admin/permissions");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("UPDATED");
        }
    }

    @Nested
    @DisplayName("deletePermission")
    class DeletePermission {

        @Test
        @DisplayName("should redirect with success message on delete")
        void success() {
            RedirectAttributes ra = new RedirectAttributesModelMap();

            String view = controller.deletePermission(1L, ra);

            assertThat(view).isEqualTo("redirect:/admin/permissions");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("1");
            verify(permissionService).deletePermission(1L);
        }

        @Test
        @DisplayName("should redirect with error when permission is assigned to roles")
        void assignedToRoles() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            doThrow(new IllegalStateException("Permission is assigned to roles"))
                    .when(permissionService).deletePermission(1L);

            String view = controller.deletePermission(1L, ra);

            assertThat(view).isEqualTo("redirect:/admin/permissions");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString()
                    .contains("Permission is assigned to roles");
        }

        @Test
        @DisplayName("should redirect with error when permission not found")
        void notFound() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            doThrow(new IllegalArgumentException("Permission not found"))
                    .when(permissionService).deletePermission(999L);

            String view = controller.deletePermission(999L, ra);

            assertThat(view).isEqualTo("redirect:/admin/permissions");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString()
                    .contains("Permission not found");
        }
    }

    @Nested
    @DisplayName("affected policies API")
    class AffectedPoliciesApi {

        @Test
        @DisplayName("public signature does not expose Map")
        void publicSignatureDoesNotExposeMap() throws Exception {
            Method method = PermissionController.class.getDeclaredMethod("getAffectedPolicies", Long.class);

            assertThat(method.getGenericReturnType().getTypeName())
                    .doesNotContain("java.util.Map");
        }

        @Test
        @DisplayName("should preserve existing response fields")
        void success() {
            Permission permission = new Permission();
            permission.setId(10L);
            permission.setName("READ_ORDER");
            Policy policy = Policy.builder()
                    .id(20L)
                    .name("OrderPolicy")
                    .effect(Policy.Effect.ALLOW)
                    .isActive(true)
                    .build();
            when(permissionRepository.findById(10L)).thenReturn(Optional.of(permission));
            when(policyRepository.findActivePoliciesReferencingExpression("READ_ORDER")).thenReturn(List.of(policy));
            when(permissionRepository.countRoleAssignments(10L)).thenReturn(3L);

            ResponseEntity<AffectedPoliciesResponse> response = controller.getAffectedPolicies(10L);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            Map<String, Object> body = toMap(response.getBody());
            assertThat(body).containsEntry("entityName", "READ_ORDER");
            assertThat(body).containsEntry("policyCount", 1);
            assertThat(body).containsEntry("roleCount", 3L);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> policies = (List<Map<String, Object>>) body.get("policies");
            assertThat(policies).hasSize(1);
            assertThat(((Number) policies.get(0).get("id")).longValue()).isEqualTo(20L);
            assertThat(policies.get(0)).containsEntry("name", "OrderPolicy");
            assertThat(policies.get(0)).containsEntry("effect", "ALLOW");
            assertThat(policies.get(0)).containsEntry("active", true);
        }

        @Test
        @DisplayName("should handle legacy policies without effect")
        void legacyPolicyWithoutEffect() {
            Permission permission = new Permission();
            permission.setId(10L);
            permission.setName("READ_ORDER");
            Policy policy = Policy.builder()
                    .id(20L)
                    .name("LegacyPolicy")
                    .effect(null)
                    .isActive(true)
                    .build();
            when(permissionRepository.findById(10L)).thenReturn(Optional.of(permission));
            when(policyRepository.findActivePoliciesReferencingExpression("READ_ORDER")).thenReturn(List.of(policy));
            when(permissionRepository.countRoleAssignments(10L)).thenReturn(0L);

            ResponseEntity<AffectedPoliciesResponse> response = controller.getAffectedPolicies(10L);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            Map<String, Object> body = toMap(response.getBody());
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> policies = (List<Map<String, Object>>) body.get("policies");
            assertThat(policies).hasSize(1);
            assertThat(policies.get(0)).containsEntry("name", "LegacyPolicy");
            assertThat(policies.get(0)).containsEntry("effect", null);
        }

        private Map<String, Object> toMap(Object body) {
            return new ObjectMapper().convertValue(body, new TypeReference<>() {
            });
        }
    }
}
