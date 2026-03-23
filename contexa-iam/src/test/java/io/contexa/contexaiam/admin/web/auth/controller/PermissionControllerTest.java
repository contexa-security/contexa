package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.metadata.service.FunctionCatalogService;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
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
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
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

    @InjectMocks
    private PermissionController controller;

    @Nested
    @DisplayName("getPermissions")
    class GetPermissions {

        @Test
        @DisplayName("should return permissions view with mapped list")
        void success() {
            Model model = new ConcurrentModel();
            Permission permission = new Permission();
            permission.setName("READ_USER");
            PermissionDto dto = PermissionDto.builder().name("READ_USER").build();

            when(permissionService.getAllPermissions()).thenReturn(List.of(permission));
            when(modelMapper.map(permission, PermissionDto.class)).thenReturn(dto);

            String view = controller.getPermissions(model);

            assertThat(view).isEqualTo("admin/permissions");
            assertThat(model.getAttribute("permissions")).isNotNull();
        }

        @Test
        @DisplayName("should map managed resource fields when present")
        void withManagedResource() {
            Model model = new ConcurrentModel();
            ManagedResource resource = new ManagedResource();
            resource.setId(10L);
            resource.setResourceIdentifier("api/users");
            Permission permission = new Permission();
            permission.setManagedResource(resource);

            PermissionDto dto = PermissionDto.builder().build();
            when(permissionService.getAllPermissions()).thenReturn(List.of(permission));
            when(modelMapper.map(permission, PermissionDto.class)).thenReturn(dto);

            String view = controller.getPermissions(model);

            assertThat(view).isEqualTo("admin/permissions");
            assertThat(dto.getManagedResourceId()).isEqualTo(10L);
            assertThat(dto.getManagedResourceIdentifier()).isEqualTo("api/users");
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

            org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
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
}
