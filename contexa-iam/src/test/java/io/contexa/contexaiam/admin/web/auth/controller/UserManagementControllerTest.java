package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexaiam.domain.dto.UserListDto;
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
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("UserManagementController")
class UserManagementControllerTest {

    @Mock
    private UserManagementService userManagementService;

    @Mock
    private RoleService roleService;

    @Mock
    private GroupService groupService;

    @InjectMocks
    private UserManagementController controller;

    @Nested
    @DisplayName("getUsers")
    class GetUsers {

        @Test
        @DisplayName("should return users view with user list")
        void success() {
            Model model = new ConcurrentModel();
            List<UserListDto> users = List.of(new UserListDto());
            when(userManagementService.getUsers()).thenReturn(users);

            String view = controller.getUsers(model);

            assertThat(view).isEqualTo("admin/users");
            assertThat(model.getAttribute("users")).isEqualTo(users);
            verify(userManagementService).getUsers();
        }
    }

    @Nested
    @DisplayName("showCreateForm")
    class ShowCreateForm {

        @Test
        @DisplayName("should return user details form with empty user and lists")
        void success() {
            Model model = new ConcurrentModel();
            List<Role> roles = List.of(new Role());
            List<Group> groups = List.of(new Group());
            when(roleService.getRolesWithoutExpression()).thenReturn(roles);
            when(groupService.getAllGroups()).thenReturn(groups);

            String view = controller.showCreateForm(model);

            assertThat(view).isEqualTo("admin/userdetails");
            assertThat(model.getAttribute("user")).isNotNull();
            assertThat(model.getAttribute("roleList")).isEqualTo(roles);
            assertThat(model.getAttribute("groupList")).isEqualTo(groups);
            assertThat(model.getAttribute("selectedGroupIds")).isEqualTo(List.of());
        }
    }

    @Nested
    @DisplayName("getUser")
    class GetUser {

        @Test
        @DisplayName("should return user details with populated data")
        void success() {
            Model model = new ConcurrentModel();
            UserDto userDto = UserDto.builder().id(1L).username("testuser").build();
            userDto.setSelectedGroupIds(List.of(10L, 20L));
            List<Role> roles = List.of(new Role());
            List<Group> groups = List.of(new Group());
            when(userManagementService.getUser(1L)).thenReturn(userDto);
            when(roleService.getRolesWithoutExpression()).thenReturn(roles);
            when(groupService.getAllGroups()).thenReturn(groups);

            String view = controller.getUser(1L, model);

            assertThat(view).isEqualTo("admin/userdetails");
            assertThat(model.getAttribute("user")).isEqualTo(userDto);
            assertThat(model.getAttribute("roleList")).isEqualTo(roles);
            assertThat(model.getAttribute("groupList")).isEqualTo(groups);
            assertThat(model.getAttribute("selectedGroupIds")).isEqualTo(List.of(10L, 20L));
        }

        @Test
        @DisplayName("should use empty list when selectedGroupIds is null")
        void nullGroupIds() {
            Model model = new ConcurrentModel();
            UserDto userDto = UserDto.builder().id(1L).build();
            userDto.setSelectedGroupIds(null);
            when(userManagementService.getUser(1L)).thenReturn(userDto);
            when(roleService.getRolesWithoutExpression()).thenReturn(List.of());
            when(groupService.getAllGroups()).thenReturn(List.of());

            String view = controller.getUser(1L, model);

            assertThat(view).isEqualTo("admin/userdetails");
            assertThat(model.getAttribute("selectedGroupIds")).isEqualTo(List.of());
        }
    }

    @Nested
    @DisplayName("updateUser")
    class UpdateUser {

        @Test
        @DisplayName("should redirect to users list on success")
        void success() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            UserDto userDto = UserDto.builder().username("testuser").build();

            String view = controller.updateUser(1L, userDto, List.of(10L), ra);

            assertThat(view).isEqualTo("redirect:/admin/users");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("testuser");
            verify(userManagementService).modifyUser(userDto);
            assertThat(userDto.getId()).isEqualTo(1L);
            assertThat(userDto.getSelectedGroupIds()).isEqualTo(List.of(10L));
        }

        @Test
        @DisplayName("should redirect to user detail on error")
        void error() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            UserDto userDto = UserDto.builder().username("testuser").build();
            doThrow(new RuntimeException("DB error")).when(userManagementService).modifyUser(any());

            String view = controller.updateUser(1L, userDto, null, ra);

            assertThat(view).isEqualTo("redirect:/admin/users/1");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("DB error");
        }
    }

    @Nested
    @DisplayName("updateUserPost")
    class UpdateUserPost {

        @Test
        @DisplayName("should delegate to updateUser")
        void delegatesToUpdateUser() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            UserDto userDto = UserDto.builder().username("testuser").build();

            String view = controller.updateUserPost(1L, userDto, List.of(10L), ra);

            assertThat(view).isEqualTo("redirect:/admin/users");
            verify(userManagementService).modifyUser(userDto);
        }
    }

    @Nested
    @DisplayName("removeUser")
    class RemoveUser {

        @Test
        @DisplayName("should redirect with success message on delete")
        void success() {
            RedirectAttributes ra = new RedirectAttributesModelMap();

            String view = controller.removeUser(1L, ra);

            assertThat(view).isEqualTo("redirect:/admin/users");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("1");
            verify(userManagementService).deleteUser(1L);
        }

        @Test
        @DisplayName("should redirect with error message on failure")
        void error() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            doThrow(new RuntimeException("Not found")).when(userManagementService).deleteUser(1L);

            String view = controller.removeUser(1L, ra);

            assertThat(view).isEqualTo("redirect:/admin/users");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("Not found");
        }
    }

    @Nested
    @DisplayName("removeUserGet")
    class RemoveUserGet {

        @Test
        @DisplayName("should delegate to removeUser")
        void delegatesToRemoveUser() {
            RedirectAttributes ra = new RedirectAttributesModelMap();

            String view = controller.removeUserGet(1L, ra);

            assertThat(view).isEqualTo("redirect:/admin/users");
            verify(userManagementService).deleteUser(1L);
        }
    }
}
