package io.contexa.contexaiam.admin.web.studio.service.impl;

import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.admin.web.studio.dto.AccessPathDto;
import io.contexa.contexaiam.admin.web.studio.dto.AccessPathNode;
import io.contexa.contexaiam.admin.web.studio.dto.EffectivePermissionDto;
import io.contexa.contexaiam.admin.web.studio.service.StudioVisualizerService;
import io.contexa.contexaiam.admin.support.context.dto.GraphDataDto;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.VirtualSubject;
import io.contexa.contexaiam.domain.dto.GroupDto;
import io.contexa.contexaiam.domain.dto.RoleDto;
import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class StudioVisualizerServiceImpl implements StudioVisualizerService {

    private final UserRepository userRepository;
    private final GroupRepository groupRepository;
    private final PermissionRepository permissionRepository;
    private final UserManagementService userManagementService;
    private final GroupService groupService;
    private final ModelMapper modelMapper;

    @Override
    public GraphDataDto analyzeAccessPathAsGraph(Long subjectId, String subjectType, Long permissionId) {
        Permission targetPermission = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new IllegalArgumentException("Permission not found with ID: " + permissionId));

        if ("USER".equalsIgnoreCase(subjectType)) {
            return analyzeUserAccessPathAsGraph(subjectId, targetPermission);
        } else if ("GROUP".equalsIgnoreCase(subjectType)) {
            return analyzeGroupAccessPathAsGraph(subjectId, targetPermission);
        } else {
            log.warn("Graph analysis for type '{}' is not supported.", subjectType);
            return new GraphDataDto(Collections.emptyList(), Collections.emptyList());
        }
    }

    private GraphDataDto analyzeUserAccessPathAsGraph(Long userId, Permission targetPermission) {
        Users user = userRepository.findByIdWithGroupsRolesAndPermissions(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + userId));

        List<GraphDataDto.Node> nodes = new ArrayList<>();
        List<GraphDataDto.Edge> edges = new ArrayList<>();
        boolean accessGranted = false;

        String userNodeId = "user_" + user.getId();
        nodes.add(new GraphDataDto.Node(userNodeId, user.getName(), "USER", Map.of("email", user.getUsername())));
        String permNodeId = "perm_" + targetPermission.getId();

        String permLabel = StringUtils.hasText(targetPermission.getDescription()) ? targetPermission.getDescription() : targetPermission.getName();

        for (UserGroup userGroup : user.getUserGroups()) {
            Group group = userGroup.getGroup();
            String groupNodeId = "group_" + group.getId();
            nodes.add(new GraphDataDto.Node(groupNodeId, group.getName(), "GROUP", Map.of("description", group.getDescription())));
            edges.add(new GraphDataDto.Edge(userNodeId, groupNodeId, "Belongs To"));

            for (GroupRole groupRole : group.getGroupRoles()) {
                Role role = groupRole.getRole();
                String roleNodeId = "role_" + role.getId();
                nodes.add(new GraphDataDto.Node(roleNodeId, role.getRoleName(), "ROLE", Map.of("description", role.getRoleDesc())));
                edges.add(new GraphDataDto.Edge(groupNodeId, roleNodeId, "Has Role"));

                if (role.getRolePermissions().stream().anyMatch(rp -> rp.getPermission().equals(targetPermission))) {
                    accessGranted = true;
                    edges.add(new GraphDataDto.Edge(roleNodeId, permNodeId, "Includes Permission (Allowed)"));
                }
            }
        }

        nodes.add(new GraphDataDto.Node(permNodeId, permLabel, "PERMISSION", Map.of("name", targetPermission.getName(), "granted", accessGranted)));

        if (!accessGranted) {
            user.getUserGroups().stream()
                    .flatMap(ug -> ug.getGroup().getGroupRoles().stream())
                    .map(gr -> "role_" + gr.getRole().getId())
                    .forEach(roleNodeId -> edges.add(new GraphDataDto.Edge(roleNodeId, permNodeId, "No Permission (Denied)")));
        }

        return new GraphDataDto(
                new ArrayList<>(new LinkedHashSet<>(nodes)),
                new ArrayList<>(new LinkedHashSet<>(edges))
        );
    }

    private GraphDataDto analyzeGroupAccessPathAsGraph(Long groupId, Permission targetPermission) {
        Group group = groupRepository.findByIdWithRoles(groupId)
                .orElseThrow(() -> new IllegalArgumentException("Group not found with ID: " + groupId));

        List<GraphDataDto.Node> nodes = new ArrayList<>();
        List<GraphDataDto.Edge> edges = new ArrayList<>();
        boolean accessGranted = false;

        String groupNodeId = "group_" + group.getId();
        nodes.add(new GraphDataDto.Node(groupNodeId, group.getName(), "GROUP", Map.of("description", group.getDescription())));
        String permNodeId = "perm_" + targetPermission.getId();

        String permLabel = StringUtils.hasText(targetPermission.getDescription()) ? targetPermission.getDescription() : targetPermission.getName();

        for (GroupRole groupRole : group.getGroupRoles()) {
            Role role = groupRole.getRole();
            String roleNodeId = "role_" + role.getId();
            nodes.add(new GraphDataDto.Node(roleNodeId, role.getRoleName(), "ROLE", Map.of("description", role.getRoleDesc())));
            edges.add(new GraphDataDto.Edge(groupNodeId, roleNodeId, "Has Role"));

            if (role.getRolePermissions().stream().anyMatch(rp -> rp.getPermission().equals(targetPermission))) {
                accessGranted = true;
                edges.add(new GraphDataDto.Edge(roleNodeId, permNodeId, "Includes Permission (Allowed)"));
            }
        }

        nodes.add(new GraphDataDto.Node(permNodeId, permLabel, "PERMISSION", Map.of("name", targetPermission.getName(), "granted", accessGranted)));

        if (!accessGranted) {
            group.getGroupRoles().stream()
                    .map(gr -> "role_" + gr.getRole().getId())
                    .forEach(roleNodeId -> edges.add(new GraphDataDto.Edge(roleNodeId, permNodeId, "No Permission (Denied)")));
        }

        return new GraphDataDto(
                new ArrayList<>(new LinkedHashSet<>(nodes)),
                new ArrayList<>(new LinkedHashSet<>(edges))
        );
    }

    @Override
    public Map<String, Object> getSubjectDetails(Long subjectId, String subjectType) {
        Map<String, Object> details = new HashMap<>();
        List<Object> assignments = new ArrayList<>();

        if ("USER".equalsIgnoreCase(subjectType)) {
            UserDto userDto = userManagementService.getUser(subjectId);
            if (userDto.getSelectedGroupIds() != null && !userDto.getSelectedGroupIds().isEmpty()) {
                List<Group> assignedGroups = groupRepository.findAllById(userDto.getSelectedGroupIds());
                List<GroupDto> groupDtos = assignedGroups.stream().map(group -> {
                    GroupDto groupDto = modelMapper.map(group, GroupDto.class);
                    
                    List<RoleDto> roleDtos = group.getGroupRoles().stream()
                            .map(gr -> modelMapper.map(gr.getRole(), RoleDto.class))
                            .collect(Collectors.toList());
                    groupDto.setRoles(roleDtos);
                    return groupDto;
                }).toList();
                assignments.addAll(groupDtos);
            }
        } else if ("GROUP".equalsIgnoreCase(subjectType)) {
            Group group = groupService.getGroup(subjectId).orElseThrow(() -> new IllegalArgumentException("Group not found with ID: " + subjectId));
            List<Role> assignedRoles = group.getGroupRoles().stream().map(GroupRole::getRole).toList();
            assignments.addAll(assignedRoles.stream().map(r -> modelMapper.map(r, RoleDto.class)).toList());
        }

        details.put("assignments", assignments);
        details.put("effectivePermissions", getEffectivePermissionsForSubject(subjectId, subjectType));
        return details;
    }

    @Override
    public AccessPathDto analyzeAccessPath(Long subjectId, String subjectType, Long permissionId) {
        Permission targetPermission = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new IllegalArgumentException("Permission not found with ID: " + permissionId));

        if ("USER".equalsIgnoreCase(subjectType)) {
            return analyzeUserAccessPath(subjectId, targetPermission);
        } else if ("GROUP".equalsIgnoreCase(subjectType)) {
            return analyzeGroupAccessPath(subjectId, targetPermission);
        } else {
            log.warn("Access path analysis for type '{}' is not supported.", subjectType);
            return new AccessPathDto(Collections.emptyList(), false, "Unsupported subject type.");
        }
    }

    private AccessPathDto analyzeUserAccessPath(Long userId, Permission targetPermission) {
        Users user = userRepository.findByIdWithGroupsRolesAndPermissions(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + userId));

        List<AccessPathNode> path = new ArrayList<>();
        path.add(new AccessPathNode("User", user.getName(), user.getUsername()));

        for (UserGroup userGroup : user.getUserGroups()) {
            Group group = userGroup.getGroup();
            for (GroupRole groupRole : group.getGroupRoles()) {
                Role role = groupRole.getRole();
                for (RolePermission rolePermission : role.getRolePermissions()) {
                    if (rolePermission.getPermission().equals(targetPermission)) {
                                                path.add(new AccessPathNode("Group", group.getName(), group.getDescription()));
                        path.add(new AccessPathNode("Role", role.getRoleName(), role.getRoleDesc()));
                        path.add(new AccessPathNode("Permission", targetPermission.getDescription(), targetPermission.getName()));
                        return new AccessPathDto(path, true, "Access allowed: Permission granted through role '" + role.getRoleName() + "'.");
                    }
                }
            }
        }

                path.add(new AccessPathNode("Permission", targetPermission.getDescription(), targetPermission.getName()));
        return new AccessPathDto(path, false, "No path found that grants this permission.");
    }

    private AccessPathDto analyzeGroupAccessPath(Long groupId, Permission targetPermission) {
        Group group = groupRepository.findByIdWithRoles(groupId)
                .orElseThrow(() -> new IllegalArgumentException("Group not found with ID: " + groupId));

        List<AccessPathNode> path = new ArrayList<>();
        path.add(new AccessPathNode("Group", group.getName(), group.getDescription()));

        for (GroupRole groupRole : group.getGroupRoles()) {
            Role role = groupRole.getRole();
            for (RolePermission rolePermission : role.getRolePermissions()) {
                if (rolePermission.getPermission().equals(targetPermission)) {
                    path.add(new AccessPathNode("Role", role.getRoleName(), role.getRoleDesc()));
                    path.add(new AccessPathNode("Permission", targetPermission.getDescription(), targetPermission.getName()));
                    return new AccessPathDto(path, true, "Access allowed: Permission granted through role '" + role.getRoleName() + "'.");
                }
            }
        }
        path.add(new AccessPathNode("Permission", targetPermission.getDescription(), targetPermission.getName()));
        return new AccessPathDto(path, false, "No path found that grants this permission.");
    }

    @Override
    public List<EffectivePermissionDto> getEffectivePermissionsForSubject(Long subjectId, String subjectType) {
        Map<String, String> permissionOrigins = new HashMap<>();
        if ("USER".equalsIgnoreCase(subjectType)) {
            Users user = userRepository.findByIdWithGroupsRolesAndPermissions(subjectId)
                    .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + subjectId));
            user.getUserGroups().forEach(ug -> {
                Group group = ug.getGroup();
                group.getGroupRoles().forEach(gr -> {
                    Role role = gr.getRole();
                    String origin = "Group: " + group.getName() + " / Role: " + role.getRoleName();
                    role.getRolePermissions().forEach(rp -> permissionOrigins.putIfAbsent(rp.getPermission().getName(), origin));
                });
            });
        } else if ("GROUP".equalsIgnoreCase(subjectType)) {
            Group group = groupRepository.findByIdWithRoles(subjectId)
                    .orElseThrow(() -> new IllegalArgumentException("Group not found with ID: " + subjectId));
            group.getGroupRoles().forEach(gr -> {
                Role role = gr.getRole();
                String origin = "Role: " + role.getRoleName();
                role.getRolePermissions().forEach(rp -> permissionOrigins.putIfAbsent(rp.getPermission().getName(), origin));
            });
        }
        if (permissionOrigins.isEmpty()) return Collections.emptyList();
        return permissionRepository.findAllByNameIn(permissionOrigins.keySet()).stream()
                .map(p -> new EffectivePermissionDto(p.getName(), p.getDescription(), permissionOrigins.get(p.getName())))
                .sorted(Comparator.comparing(EffectivePermissionDto::permissionName))
                .collect(Collectors.toList());
    }

    @Override
    public List<EffectivePermissionDto> getEffectivePermissionsForSubject(VirtualSubject subject) {
        Map<String, String> permissionOrigins = new HashMap<>();

        subject.getVirtualGroups().forEach(group -> {
            group.getGroupRoles().forEach(gr -> { 
                Role role = gr.getRole();
                String origin = "Group: " + group.getName() + " / Role: " + role.getRoleName();
                role.getRolePermissions().forEach(rp ->
                        permissionOrigins.putIfAbsent(rp.getPermission().getName(), origin)
                );
            });
        });

        if(permissionOrigins.isEmpty()) {
            return Collections.emptyList();
        }

        return permissionRepository.findAllByNameIn(permissionOrigins.keySet()).stream()
                .map(p -> new EffectivePermissionDto(p.getName(), p.getDescription(), permissionOrigins.get(p.getName())))
                .sorted(Comparator.comparing(EffectivePermissionDto::permissionName))
                .collect(Collectors.toList());
    }
}