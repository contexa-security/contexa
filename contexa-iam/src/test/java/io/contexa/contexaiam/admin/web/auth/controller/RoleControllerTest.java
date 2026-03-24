package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.domain.dto.RoleDto;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.RolePermission;
import io.contexa.contexacommon.repository.RoleRepository;
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
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("RoleController")
class RoleControllerTest {

    @Mock
    private RoleService roleService;

    @Mock
    private PermissionService permissionService;

    @Mock
    private ModelMapper modelMapper;

    @Mock
    private RoleRepository roleRepository;

    @InjectMocks
    private RoleController controller;

    @Nested
    @DisplayName("getRoles")
    class GetRoles {

        @Test
        @DisplayName("should return roles view with mapped role list")
        void success() {
            Model model = new ConcurrentModel();
            Pageable pageable = PageRequest.of(0, 15);
            Role role = new Role();
            role.setRolePermissions(Set.of(new RolePermission()));

            RoleDto dto = RoleDto.builder().roleName("ADMIN").build();
            when(roleRepository.findAll(pageable)).thenReturn(new PageImpl<>(List.of(role)));
            when(modelMapper.map(role, RoleDto.class)).thenReturn(dto);

            String view = controller.getRoles(null, pageable, model);

            assertThat(view).isEqualTo("admin/roles");
            assertThat(model.getAttribute("roles")).isNotNull();
        }

        @Test
        @DisplayName("should handle roles with null permissions")
        void nullPermissions() {
            Model model = new ConcurrentModel();
            Pageable pageable = PageRequest.of(0, 15);
            Role role = new Role();
            role.setRolePermissions(null);

            RoleDto dto = RoleDto.builder().build();
            when(roleRepository.findAll(pageable)).thenReturn(new PageImpl<>(List.of(role)));
            when(modelMapper.map(role, RoleDto.class)).thenReturn(dto);

            String view = controller.getRoles(null, pageable, model);

            assertThat(view).isEqualTo("admin/roles");
            assertThat(dto.getPermissionCount()).isZero();
        }
    }

    @Nested
    @DisplayName("registerRoleForm")
    class RegisterRoleForm {

        @Test
        @DisplayName("should return role form with empty role and permissions")
        void success() {
            Model model = new ConcurrentModel();
            List<Permission> permissions = List.of(new Permission());
            when(permissionService.getAllPermissions()).thenReturn(permissions);

            String view = controller.registerRoleForm(model);

            assertThat(view).isEqualTo("admin/rolesdetails");
            assertThat(model.getAttribute("role")).isInstanceOf(RoleDto.class);
            assertThat(model.getAttribute("permissionList")).isEqualTo(permissions);
            assertThat(model.getAttribute("selectedPermissionIds")).isInstanceOf(ArrayList.class);
        }
    }

    @Nested
    @DisplayName("createRole")
    class CreateRole {

        @Test
        @DisplayName("should redirect with success message on creation")
        void success() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            RoleDto roleDto = RoleDto.builder().roleName("ADMIN").permissionIds(List.of(1L)).build();
            Role role = new Role();
            when(modelMapper.map(roleDto, Role.class)).thenReturn(role);

            String view = controller.createRole(roleDto, ra);

            assertThat(view).isEqualTo("redirect:/admin/roles");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("successfully created");
            verify(roleService).createRole(role, List.of(1L));
        }
    }

    @Nested
    @DisplayName("getRoleDetails")
    class GetRoleDetails {

        @Test
        @DisplayName("should return role details with permissions")
        void success() {
            Model model = new ConcurrentModel();
            Permission perm = new Permission();
            perm.setId(5L);
            RolePermission rp = new RolePermission();
            rp.setPermission(perm);
            Role role = new Role();
            role.setRolePermissions(Set.of(rp));

            RoleDto roleDto = RoleDto.builder().roleName("ADMIN").build();
            PermissionDto permDto = PermissionDto.builder().id(5L).build();

            when(roleService.getRole(1L)).thenReturn(role);
            when(modelMapper.map(role, RoleDto.class)).thenReturn(roleDto);
            when(permissionService.getAllPermissions()).thenReturn(List.of(perm));
            when(modelMapper.map(perm, PermissionDto.class)).thenReturn(permDto);

            String view = controller.getRoleDetails(1L, model);

            assertThat(view).isEqualTo("admin/rolesdetails");
            assertThat(model.getAttribute("role")).isEqualTo(roleDto);
            assertThat(model.getAttribute("permissionList")).isNotNull();
            assertThat(model.getAttribute("selectedPermissionIds")).isNotNull();
        }
    }

    @Nested
    @DisplayName("updateRole")
    class UpdateRole {

        @Test
        @DisplayName("should redirect with success message on update")
        void success() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            RoleDto roleDto = RoleDto.builder().roleName("ADMIN").permissionIds(List.of(2L)).build();
            Role role = new Role();
            when(modelMapper.map(roleDto, Role.class)).thenReturn(role);

            String view = controller.updateRole(1L, roleDto, ra);

            assertThat(view).isEqualTo("redirect:/admin/roles");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("successfully updated");
            assertThat(roleDto.getId()).isEqualTo(1L);
            verify(roleService).updateRole(role, List.of(2L));
        }
    }

    @Nested
    @DisplayName("deleteRole")
    class DeleteRole {

        @Test
        @DisplayName("should redirect with success message on delete")
        void success() {
            RedirectAttributes ra = new RedirectAttributesModelMap();

            String view = controller.deleteRole(1L, ra);

            assertThat(view).isEqualTo("redirect:/admin/roles");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("successfully deleted");
            verify(roleService).deleteRole(1L);
        }
    }
}
