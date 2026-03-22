package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.impl.RoleHierarchyService;
import io.contexa.contexaiam.domain.dto.RoleHierarchyDto;
import io.contexa.contexaiam.domain.entity.RoleHierarchyEntity;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Role;
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

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RoleHierarchyControllerTest {

    @Mock
    private RoleHierarchyService roleHierarchyService;

    @Mock
    private ModelMapper modelMapper;

    @Mock
    private RoleService roleService;

    @Mock
    private GroupService groupService;

    @InjectMocks
    private RoleHierarchyController controller;

    // ===== Helpers =====

    private RoleHierarchyEntity buildEntity(Long id, String hs, String desc, boolean active) {
        return RoleHierarchyEntity.builder()
                .id(id).hierarchyString(hs).description(desc).isActive(active).build();
    }

    private RoleHierarchyDto buildDto(Long id, String hs, String desc, boolean active) {
        return RoleHierarchyDto.builder()
                .id(id).hierarchyString(hs).description(desc).isActive(active).build();
    }

    private void stubFormModelDependencies() {
        when(groupService.getAllGroups()).thenReturn(Collections.emptyList());
        when(roleService.getRolesWithoutExpression()).thenReturn(Collections.emptyList());
        when(roleHierarchyService.getAllRoleHierarchies()).thenReturn(Collections.emptyList());
    }

    // =========================================================================
    // 1. GET /admin/role-hierarchies - List
    // =========================================================================

    @Nested
    @DisplayName("GET /admin/role-hierarchies")
    class ListHierarchies {

        @Test
        @DisplayName("should return list view with hierarchies")
        void shouldReturnListView() {
            RoleHierarchyEntity entity = buildEntity(1L, "ROLE_ADMIN > ROLE_USER", "H1", true);
            when(roleHierarchyService.getAllRoleHierarchies()).thenReturn(List.of(entity));

            RoleHierarchyDto dto = buildDto(1L, "ROLE_ADMIN > ROLE_USER", "H1", true);
            when(modelMapper.map(any(RoleHierarchyEntity.class), eq(RoleHierarchyDto.class))).thenReturn(dto);

            Model model = new ConcurrentModel();
            String viewName = controller.getRoleHierarchies(model);

            assertThat(viewName).isEqualTo("admin/role-hierarchies");
            assertThat(model.getAttribute("hierarchies")).isNotNull();
            @SuppressWarnings("unchecked")
            List<RoleHierarchyDto> list = (List<RoleHierarchyDto>) model.getAttribute("hierarchies");
            assertThat(list).hasSize(1);
        }

        @Test
        @DisplayName("should return empty list when no hierarchies")
        void shouldReturnEmptyList() {
            when(roleHierarchyService.getAllRoleHierarchies()).thenReturn(Collections.emptyList());

            Model model = new ConcurrentModel();
            String viewName = controller.getRoleHierarchies(model);

            assertThat(viewName).isEqualTo("admin/role-hierarchies");
            @SuppressWarnings("unchecked")
            List<RoleHierarchyDto> list = (List<RoleHierarchyDto>) model.getAttribute("hierarchies");
            assertThat(list).isEmpty();
        }
    }

    // =========================================================================
    // 2. GET /admin/role-hierarchies/register - Register form
    // =========================================================================

    @Nested
    @DisplayName("GET /admin/role-hierarchies/register")
    class RegisterForm {

        @Test
        @DisplayName("should return register form with empty dto")
        void shouldReturnRegisterForm() {
            stubFormModelDependencies();

            Model model = new ConcurrentModel();
            String viewName = controller.registerRoleHierarchyForm(model);

            assertThat(viewName).isEqualTo("admin/role-hierarchy-details");
            assertThat(model.getAttribute("hierarchy")).isNotNull();
            assertThat(model.getAttribute("hierarchy")).isInstanceOf(RoleHierarchyDto.class);
        }
    }

    // =========================================================================
    // 3. POST /admin/role-hierarchies - Create
    // =========================================================================

    @Nested
    @DisplayName("POST /admin/role-hierarchies")
    class CreateHierarchy {

        @Test
        @DisplayName("should redirect to list on success")
        void shouldRedirectOnSuccess() {
            RoleHierarchyDto dto = buildDto(null, "ROLE_ADMIN > ROLE_USER", "H1", false);
            RoleHierarchyEntity entity = buildEntity(null, "ROLE_ADMIN > ROLE_USER", "H1", false);
            when(modelMapper.map(any(RoleHierarchyDto.class), eq(RoleHierarchyEntity.class))).thenReturn(entity);
            when(roleHierarchyService.createRoleHierarchy(any())).thenReturn(entity);

            RedirectAttributes ra = new RedirectAttributesModelMap();
            String viewName = controller.createRoleHierarchy(dto, ra);

            assertThat(viewName).isEqualTo("redirect:/admin/role-hierarchies");
            assertThat(ra.getFlashAttributes()).containsKey("message");
        }

        @Test
        @DisplayName("should redirect to register with error on validation failure")
        void shouldRedirectOnError() {
            RoleHierarchyDto dto = buildDto(null, "ROLE_A > ROLE_B\nROLE_B > ROLE_A", "Bad", false);
            RoleHierarchyEntity entity = buildEntity(null, "ROLE_A > ROLE_B\nROLE_B > ROLE_A", "Bad", false);
            when(modelMapper.map(any(RoleHierarchyDto.class), eq(RoleHierarchyEntity.class))).thenReturn(entity);
            when(roleHierarchyService.createRoleHierarchy(any()))
                    .thenThrow(new IllegalArgumentException("Reverse relationship found"));

            RedirectAttributes ra = new RedirectAttributesModelMap();
            String viewName = controller.createRoleHierarchy(dto, ra);

            assertThat(viewName).isEqualTo("redirect:/admin/role-hierarchies/register");
            assertThat(ra.getFlashAttributes()).containsKey("error");
        }
    }

    // =========================================================================
    // 4. GET /admin/role-hierarchies/{id} - Details
    // =========================================================================

    @Nested
    @DisplayName("GET /admin/role-hierarchies/{id}")
    class HierarchyDetails {

        @Test
        @DisplayName("should return details view with parsed pairs")
        void shouldReturnDetails() {
            RoleHierarchyEntity entity = buildEntity(1L, "ROLE_ADMIN > ROLE_USER", "H1", true);
            when(roleHierarchyService.getRoleHierarchy(1L)).thenReturn(Optional.of(entity));

            RoleHierarchyDto dto = buildDto(1L, "ROLE_ADMIN > ROLE_USER", "H1", true);
            when(modelMapper.map(any(RoleHierarchyEntity.class), eq(RoleHierarchyDto.class))).thenReturn(dto);
            stubFormModelDependencies();

            Model model = new ConcurrentModel();
            String viewName = controller.roleHierarchyDetails(1L, model);

            assertThat(viewName).isEqualTo("admin/role-hierarchy-details");
            assertThat(model.getAttribute("hierarchy")).isNotNull();
        }

        @Test
        @DisplayName("should parse multi-line hierarchy into pairs")
        void shouldParseMultiLinePairs() {
            String hs = "ROLE_ADMIN > ROLE_MANAGER\nROLE_MANAGER > ROLE_USER";
            RoleHierarchyEntity entity = buildEntity(1L, hs, "Multi", true);
            when(roleHierarchyService.getRoleHierarchy(1L)).thenReturn(Optional.of(entity));

            RoleHierarchyDto dto = buildDto(1L, hs, "Multi", true);
            when(modelMapper.map(any(RoleHierarchyEntity.class), eq(RoleHierarchyDto.class))).thenReturn(dto);
            stubFormModelDependencies();

            Model model = new ConcurrentModel();
            controller.roleHierarchyDetails(1L, model);

            RoleHierarchyDto resultDto = (RoleHierarchyDto) model.getAttribute("hierarchy");
            assertThat(resultDto.getHierarchyPairs()).hasSize(2);
        }

        @Test
        @DisplayName("should redirect on invalid ID")
        void shouldRedirectOnInvalidId() {
            when(roleHierarchyService.getRoleHierarchy(999L)).thenReturn(Optional.empty());

            Model model = new ConcurrentModel();
            String viewName = controller.roleHierarchyDetails(999L, model);

            assertThat(viewName).isEqualTo("redirect:/admin/role-hierarchies");
        }

        @Test
        @DisplayName("should handle escaped newlines in hierarchy string")
        void shouldHandleEscapedNewlines() {
            String hs = "ROLE_ADMIN > ROLE_USER\\nROLE_USER > ROLE_DEV";
            RoleHierarchyEntity entity = buildEntity(1L, hs, "Escaped", true);
            when(roleHierarchyService.getRoleHierarchy(1L)).thenReturn(Optional.of(entity));

            RoleHierarchyDto dto = buildDto(1L, hs, "Escaped", true);
            when(modelMapper.map(any(RoleHierarchyEntity.class), eq(RoleHierarchyDto.class))).thenReturn(dto);
            stubFormModelDependencies();

            Model model = new ConcurrentModel();
            controller.roleHierarchyDetails(1L, model);

            RoleHierarchyDto resultDto = (RoleHierarchyDto) model.getAttribute("hierarchy");
            assertThat(resultDto.getHierarchyPairs()).hasSize(2);
        }
    }

    // =========================================================================
    // 5. POST /admin/role-hierarchies/{id}/edit - Update
    // =========================================================================

    @Nested
    @DisplayName("POST /admin/role-hierarchies/{id}/edit")
    class UpdateHierarchy {

        @Test
        @DisplayName("should redirect to list on success")
        void shouldRedirectOnSuccess() {
            RoleHierarchyDto dto = buildDto(null, "ROLE_ADMIN > ROLE_USER", "Updated", true);
            RoleHierarchyEntity entity = buildEntity(1L, "ROLE_ADMIN > ROLE_USER", "Updated", true);
            when(modelMapper.map(any(RoleHierarchyDto.class), eq(RoleHierarchyEntity.class))).thenReturn(entity);
            when(roleHierarchyService.updateRoleHierarchy(any())).thenReturn(entity);

            RedirectAttributes ra = new RedirectAttributesModelMap();
            String viewName = controller.updateRoleHierarchy(1L, dto, ra);

            assertThat(viewName).isEqualTo("redirect:/admin/role-hierarchies");
            assertThat(ra.getFlashAttributes()).containsKey("message");
        }

        @Test
        @DisplayName("should set ID from path variable")
        void shouldSetIdFromPath() {
            RoleHierarchyDto dto = buildDto(null, "ROLE_ADMIN > ROLE_USER", "Test", true);
            RoleHierarchyEntity entity = buildEntity(5L, "ROLE_ADMIN > ROLE_USER", "Test", true);
            when(modelMapper.map(any(RoleHierarchyDto.class), eq(RoleHierarchyEntity.class))).thenReturn(entity);
            when(roleHierarchyService.updateRoleHierarchy(any())).thenReturn(entity);

            RedirectAttributes ra = new RedirectAttributesModelMap();
            controller.updateRoleHierarchy(5L, dto, ra);

            assertThat(dto.getId()).isEqualTo(5L);
        }

        @Test
        @DisplayName("should redirect to details with error on failure")
        void shouldRedirectOnError() {
            RoleHierarchyDto dto = buildDto(null, "BAD", "Test", true);
            RoleHierarchyEntity entity = buildEntity(1L, "BAD", "Test", true);
            when(modelMapper.map(any(RoleHierarchyDto.class), eq(RoleHierarchyEntity.class))).thenReturn(entity);
            when(roleHierarchyService.updateRoleHierarchy(any()))
                    .thenThrow(new IllegalArgumentException("Validation failed"));

            RedirectAttributes ra = new RedirectAttributesModelMap();
            String viewName = controller.updateRoleHierarchy(1L, dto, ra);

            assertThat(viewName).isEqualTo("redirect:/admin/role-hierarchies/1");
            assertThat(ra.getFlashAttributes()).containsKey("error");
        }
    }

    // =========================================================================
    // 6. POST /admin/role-hierarchies/delete/{id} - Delete
    // =========================================================================

    @Nested
    @DisplayName("POST /admin/role-hierarchies/delete/{id}")
    class DeleteHierarchy {

        @Test
        @DisplayName("should delete and redirect with success message")
        void shouldDeleteAndRedirect() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            String viewName = controller.deleteRoleHierarchy(1L, ra);

            assertThat(viewName).isEqualTo("redirect:/admin/role-hierarchies");
            verify(roleHierarchyService).deleteRoleHierarchy(1L);
            assertThat(ra.getFlashAttributes().get("message").toString()).contains("1");
        }
    }

    // =========================================================================
    // 7. POST /admin/role-hierarchies/{id}/activate - Activate/Deactivate
    // =========================================================================

    @Nested
    @DisplayName("POST /admin/role-hierarchies/{id}/activate")
    class ActivateHierarchy {

        @Test
        @DisplayName("should return activated message when toggled to active")
        void shouldActivate() {
            when(roleHierarchyService.activateRoleHierarchy(1L)).thenReturn(true);

            RedirectAttributes ra = new RedirectAttributesModelMap();
            String viewName = controller.activateRoleHierarchy(1L, ra);

            assertThat(viewName).isEqualTo("redirect:/admin/role-hierarchies");
            assertThat(ra.getFlashAttributes().get("message").toString()).contains("activated");
        }

        @Test
        @DisplayName("should return deactivated message when toggled to inactive")
        void shouldDeactivate() {
            when(roleHierarchyService.activateRoleHierarchy(1L)).thenReturn(false);

            RedirectAttributes ra = new RedirectAttributesModelMap();
            String viewName = controller.activateRoleHierarchy(1L, ra);

            assertThat(viewName).isEqualTo("redirect:/admin/role-hierarchies");
            assertThat(ra.getFlashAttributes().get("message").toString()).contains("deactivated");
        }

        @Test
        @DisplayName("should set error message on validation failure")
        void shouldSetErrorOnFailure() {
            when(roleHierarchyService.activateRoleHierarchy(1L))
                    .thenThrow(new IllegalArgumentException("Circular reference detected"));

            RedirectAttributes ra = new RedirectAttributesModelMap();
            String viewName = controller.activateRoleHierarchy(1L, ra);

            assertThat(viewName).isEqualTo("redirect:/admin/role-hierarchies");
            assertThat(ra.getFlashAttributes()).containsKey("error");
        }
    }
}
