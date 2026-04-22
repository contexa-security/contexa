package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.domain.dto.GroupDto;
import io.contexa.contexaiam.domain.dto.RoleMetadataDto;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.GroupRole;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.repository.GroupRepository;
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

import java.util.Locale;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("GroupController")
class GroupControllerTest {

    @Mock
    private GroupService groupService;

    @Mock
    private RoleService roleService;

    @Mock
    private ModelMapper modelMapper;

    @Mock
    private GroupRepository groupRepository;

    @Mock
    private MessageSource messageSource;

    @InjectMocks
    private GroupController controller;

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
    @DisplayName("getGroups")
    class GetGroups {

        @Test
        @DisplayName("should return groups view with mapped group list")
        void success() {
            Model model = new ConcurrentModel();
            Pageable pageable = PageRequest.of(0, 15);
            Group group = new Group();
            group.setName("TestGroup");
            group.setGroupRoles(Set.of(new GroupRole()));
            group.setUserGroups(Set.of(new UserGroup()));

            GroupDto dto = GroupDto.builder().name("TestGroup").build();
            when(groupRepository.findAll(pageable)).thenReturn(new PageImpl<>(List.of(group)));
            when(modelMapper.map(group, GroupDto.class)).thenReturn(dto);

            String view = controller.getGroups(null, pageable, model);

            assertThat(view).isEqualTo("admin/groups");
            assertThat(model.getAttribute("groups")).isNotNull();
            verify(groupRepository).findAll(pageable);
        }

        @Test
        @DisplayName("should handle groups with null roles and userGroups")
        void nullCollections() {
            Model model = new ConcurrentModel();
            Pageable pageable = PageRequest.of(0, 15);
            Group group = new Group();
            group.setGroupRoles(null);
            group.setUserGroups(null);

            GroupDto dto = GroupDto.builder().build();
            when(groupRepository.findAll(pageable)).thenReturn(new PageImpl<>(List.of(group)));
            when(modelMapper.map(group, GroupDto.class)).thenReturn(dto);

            String view = controller.getGroups(null, pageable, model);

            assertThat(view).isEqualTo("admin/groups");
            assertThat(dto.getRoleCount()).isZero();
            assertThat(dto.getUserCount()).isZero();
        }
    }

    @Nested
    @DisplayName("registerGroupForm")
    class RegisterGroupForm {

        @Test
        @DisplayName("should return group details form with empty group")
        void success() {
            Model model = new ConcurrentModel();
            List<Role> roles = List.of(new Role());
            when(roleService.getRoles()).thenReturn(roles);

            String view = controller.registerGroupForm(model);

            assertThat(view).isEqualTo("admin/groupdetails");
            assertThat(model.getAttribute("group")).isInstanceOf(GroupDto.class);
            assertThat(model.getAttribute("roleList")).isEqualTo(roles);
            assertThat(model.getAttribute("selectedRoleIds")).isInstanceOf(HashSet.class);
        }
    }

    @Nested
    @DisplayName("createGroup")
    class CreateGroup {

        @Test
        @DisplayName("should redirect with success message on creation")
        void success() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            GroupDto groupDto = GroupDto.builder().name("NewGroup").build();
            Group group = new Group();
            group.setName("NewGroup");
            when(modelMapper.map(groupDto, Group.class)).thenReturn(group);

            String view = controller.createGroup(groupDto, List.of(1L), ra);

            assertThat(view).isEqualTo("redirect:/admin/groups");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("NewGroup");
            verify(groupService).createGroup(group, List.of(1L));
        }

        @Test
        @DisplayName("should redirect with error on IllegalArgumentException")
        void illegalArgument() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            GroupDto groupDto = GroupDto.builder().name("BadGroup").build();
            Group group = new Group();
            when(modelMapper.map(groupDto, Group.class)).thenReturn(group);
            doThrow(new IllegalArgumentException("Duplicate name")).when(groupService).createGroup(any(), any());

            String view = controller.createGroup(groupDto, null, ra);

            assertThat(view).isEqualTo("redirect:/admin/groups");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("Duplicate name");
        }

        @Test
        @DisplayName("should redirect with error on unexpected exception")
        void unexpectedException() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            GroupDto groupDto = GroupDto.builder().build();
            Group group = new Group();
            when(modelMapper.map(groupDto, Group.class)).thenReturn(group);
            doThrow(new RuntimeException("DB error")).when(groupService).createGroup(any(), any());

            String view = controller.createGroup(groupDto, null, ra);

            assertThat(view).isEqualTo("redirect:/admin/groups");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("DB error");
        }
    }

    @Nested
    @DisplayName("getGroupDetails")
    class GetGroupDetails {

        @Test
        @DisplayName("should return group details with roles")
        void success() {
            Model model = new ConcurrentModel();
            Role role = new Role();
            role.setId(5L);
            GroupRole groupRole = new GroupRole();
            groupRole.setRole(role);
            Group group = new Group();
            group.setGroupRoles(Set.of(groupRole));

            GroupDto groupDto = GroupDto.builder().name("TestGroup").build();
            RoleMetadataDto roleMetaDto = new RoleMetadataDto();

            when(groupService.getGroup(1L)).thenReturn(Optional.of(group));
            when(roleService.getRoles()).thenReturn(List.of(role));
            when(modelMapper.map(group, GroupDto.class)).thenReturn(groupDto);
            when(modelMapper.map(role, RoleMetadataDto.class)).thenReturn(roleMetaDto);
            RedirectAttributes ra = new RedirectAttributesModelMap();

            String view = controller.getGroupDetails(1L, model, ra);

            assertThat(view).isEqualTo("admin/groupdetails");
            assertThat(model.getAttribute("group")).isEqualTo(groupDto);
            assertThat(model.getAttribute("roleList")).isNotNull();
            assertThat(model.getAttribute("selectedRoleIds")).isNotNull();
        }

        @Test
        @DisplayName("should redirect with error for invalid group ID")
        void invalidId() {
            Model model = new ConcurrentModel();
            RedirectAttributes ra = new RedirectAttributesModelMap();
            when(groupService.getGroup(999L)).thenReturn(Optional.empty());

            String view = controller.getGroupDetails(999L, model, ra);

            assertThat(view).isEqualTo("redirect:/admin/groups");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("999");
        }

        @Test
        @DisplayName("should return group details when group roles are null")
        void nullGroupRoles() {
            Model model = new ConcurrentModel();
            Group group = new Group();
            group.setGroupRoles(null);
            GroupDto groupDto = GroupDto.builder().name("NoRoles").build();
            when(groupService.getGroup(1L)).thenReturn(Optional.of(group));
            when(roleService.getRoles()).thenReturn(List.of());
            when(modelMapper.map(group, GroupDto.class)).thenReturn(groupDto);
            RedirectAttributes ra = new RedirectAttributesModelMap();

            String view = controller.getGroupDetails(1L, model, ra);

            assertThat(view).isEqualTo("admin/groupdetails");
            assertThat(model.getAttribute("selectedRoleIds")).isEqualTo(List.of());
        }
    }

    @Nested
    @DisplayName("updateGroup")
    class UpdateGroup {

        @Test
        @DisplayName("should redirect with success message on update")
        void success() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            GroupDto groupDto = GroupDto.builder().name("Updated").build();
            Group group = new Group();
            group.setName("Updated");
            when(modelMapper.map(groupDto, Group.class)).thenReturn(group);

            String view = controller.updateGroup(1L, groupDto, List.of(2L), ra);

            assertThat(view).isEqualTo("redirect:/admin/groups");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("Updated");
            assertThat(groupDto.getId()).isEqualTo(1L);
            verify(groupService).updateGroup(group, List.of(2L));
        }

        @Test
        @DisplayName("should redirect with error on IllegalArgumentException")
        void illegalArgument() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            GroupDto groupDto = GroupDto.builder().build();
            Group group = new Group();
            when(modelMapper.map(groupDto, Group.class)).thenReturn(group);
            doThrow(new IllegalArgumentException("Not found")).when(groupService).updateGroup(any(), any());

            String view = controller.updateGroup(1L, groupDto, null, ra);

            assertThat(view).isEqualTo("redirect:/admin/groups");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("Not found");
        }

        @Test
        @DisplayName("should redirect with error on unexpected exception")
        void unexpectedException() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            GroupDto groupDto = GroupDto.builder().build();
            Group group = new Group();
            when(modelMapper.map(groupDto, Group.class)).thenReturn(group);
            doThrow(new RuntimeException("DB error")).when(groupService).updateGroup(any(), any());

            String view = controller.updateGroup(1L, groupDto, null, ra);

            assertThat(view).isEqualTo("redirect:/admin/groups");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("DB error");
        }
    }

    @Nested
    @DisplayName("deleteGroup")
    class DeleteGroup {

        @Test
        @DisplayName("should redirect with success message on delete")
        void success() {
            RedirectAttributes ra = new RedirectAttributesModelMap();

            String view = controller.deleteGroup(1L, ra);

            assertThat(view).isEqualTo("redirect:/admin/groups");
            assertThat(ra.getFlashAttributes().get("message")).asString().contains("1");
            verify(groupService).deleteGroup(1L);
        }

        @Test
        @DisplayName("should redirect with error message on failure")
        void error() {
            RedirectAttributes ra = new RedirectAttributesModelMap();
            doThrow(new RuntimeException("Constraint violation")).when(groupService).deleteGroup(1L);

            String view = controller.deleteGroup(1L, ra);

            assertThat(view).isEqualTo("redirect:/admin/groups");
            assertThat(ra.getFlashAttributes().get("errorMessage")).asString().contains("Constraint violation");
        }
    }
}
