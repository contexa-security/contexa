package io.contexa.contexaiam.admin.web.studio.service.impl;

import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.admin.web.studio.dto.AccessPathDto;
import io.contexa.contexaiam.admin.web.studio.dto.AccessPathNode;
import io.contexa.contexaiam.admin.web.studio.dto.EffectivePermissionDto;
import io.contexa.contexaiam.admin.web.studio.service.StudioVisualizerService;
import io.contexa.contexaiam.admin.support.visualization.dto.GraphDataDto;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.VirtualSubject;
import io.contexa.contexaiam.domain.dto.GroupDto;
import io.contexa.contexaiam.domain.dto.RoleDto;
import io.contexa.contexaiam.domain.dto.UserDto;
import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
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

        // [핵심 수정] 권한 라벨이 null이 되지 않도록 처리
        String permLabel = StringUtils.hasText(targetPermission.getDescription()) ? targetPermission.getDescription() : targetPermission.getName();

        for (UserGroup userGroup : user.getUserGroups()) {
            Group group = userGroup.getGroup();
            String groupNodeId = "group_" + group.getId();
            nodes.add(new GraphDataDto.Node(groupNodeId, group.getName(), "GROUP", Map.of("description", group.getDescription())));
            edges.add(new GraphDataDto.Edge(userNodeId, groupNodeId, "소속"));

            for (GroupRole groupRole : group.getGroupRoles()) {
                Role role = groupRole.getRole();
                String roleNodeId = "role_" + role.getId();
                nodes.add(new GraphDataDto.Node(roleNodeId, role.getRoleName(), "ROLE", Map.of("description", role.getRoleDesc())));
                edges.add(new GraphDataDto.Edge(groupNodeId, roleNodeId, "역할 보유"));

                if (role.getRolePermissions().stream().anyMatch(rp -> rp.getPermission().equals(targetPermission))) {
                    accessGranted = true;
                    edges.add(new GraphDataDto.Edge(roleNodeId, permNodeId, "권한 포함 (허용)"));
                }
            }
        }

        nodes.add(new GraphDataDto.Node(permNodeId, permLabel, "PERMISSION", Map.of("name", targetPermission.getName(), "granted", accessGranted)));

        if (!accessGranted) {
            user.getUserGroups().stream()
                    .flatMap(ug -> ug.getGroup().getGroupRoles().stream())
                    .map(gr -> "role_" + gr.getRole().getId())
                    .forEach(roleNodeId -> edges.add(new GraphDataDto.Edge(roleNodeId, permNodeId, "권한 없음 (거부)")));
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

        // [핵심 수정] 권한 라벨이 null이 되지 않도록 처리
        String permLabel = StringUtils.hasText(targetPermission.getDescription()) ? targetPermission.getDescription() : targetPermission.getName();

        for (GroupRole groupRole : group.getGroupRoles()) {
            Role role = groupRole.getRole();
            String roleNodeId = "role_" + role.getId();
            nodes.add(new GraphDataDto.Node(roleNodeId, role.getRoleName(), "ROLE", Map.of("description", role.getRoleDesc())));
            edges.add(new GraphDataDto.Edge(groupNodeId, roleNodeId, "역할 보유"));

            if (role.getRolePermissions().stream().anyMatch(rp -> rp.getPermission().equals(targetPermission))) {
                accessGranted = true;
                edges.add(new GraphDataDto.Edge(roleNodeId, permNodeId, "권한 포함 (허용)"));
            }
        }

        nodes.add(new GraphDataDto.Node(permNodeId, permLabel, "PERMISSION", Map.of("name", targetPermission.getName(), "granted", accessGranted)));

        if (!accessGranted) {
            group.getGroupRoles().stream()
                    .map(gr -> "role_" + gr.getRole().getId())
                    .forEach(roleNodeId -> edges.add(new GraphDataDto.Edge(roleNodeId, permNodeId, "권한 없음 (거부)")));
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
                    // 그룹이 가진 역할들을 RoleDto로 변환하여 리스트에 추가
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

    // =================================================================
    //                    기존 메서드 (하위 호환성을 위해 유지)
    // =================================================================

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
            return new AccessPathDto(Collections.emptyList(), false, "지원하지 않는 주체 타입입니다.");
        }
    }

    private AccessPathDto analyzeUserAccessPath(Long userId, Permission targetPermission) {
        Users user = userRepository.findByIdWithGroupsRolesAndPermissions(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + userId));

        List<AccessPathNode> path = new ArrayList<>();
        path.add(new AccessPathNode("사용자", user.getName(), user.getUsername()));

        for (UserGroup userGroup : user.getUserGroups()) {
            Group group = userGroup.getGroup();
            for (GroupRole groupRole : group.getGroupRoles()) {
                Role role = groupRole.getRole();
                for (RolePermission rolePermission : role.getRolePermissions()) {
                    if (rolePermission.getPermission().equals(targetPermission)) {
                        log.debug("Access path found for user {} to permission {} via role {}", user.getUsername(), targetPermission.getName(), role.getRoleName());
                        path.add(new AccessPathNode("그룹", group.getName(), group.getDescription()));
                        path.add(new AccessPathNode("역할", role.getRoleName(), role.getRoleDesc()));
                        path.add(new AccessPathNode("권한", targetPermission.getDescription(), targetPermission.getName()));
                        return new AccessPathDto(path, true, "접근 허용: 역할 '" + role.getRoleName() + "'을 통해 권한이 부여되었습니다.");
                    }
                }
            }
        }

        log.debug("No access path found for user {} to permission {}", user.getUsername(), targetPermission.getName());
        path.add(new AccessPathNode("권한", targetPermission.getDescription(), targetPermission.getName()));
        return new AccessPathDto(path, false, "해당 권한을 부여하는 경로를 찾을 수 없습니다.");
    }

    private AccessPathDto analyzeGroupAccessPath(Long groupId, Permission targetPermission) {
        Group group = groupRepository.findByIdWithRoles(groupId)
                .orElseThrow(() -> new IllegalArgumentException("Group not found with ID: " + groupId));

        List<AccessPathNode> path = new ArrayList<>();
        path.add(new AccessPathNode("그룹", group.getName(), group.getDescription()));

        for (GroupRole groupRole : group.getGroupRoles()) {
            Role role = groupRole.getRole();
            for (RolePermission rolePermission : role.getRolePermissions()) {
                if (rolePermission.getPermission().equals(targetPermission)) {
                    path.add(new AccessPathNode("역할", role.getRoleName(), role.getRoleDesc()));
                    path.add(new AccessPathNode("권한", targetPermission.getDescription(), targetPermission.getName()));
                    return new AccessPathDto(path, true, "접근 허용: 역할 '" + role.getRoleName() + "'을 통해 권한이 부여됩니다.");
                }
            }
        }
        path.add(new AccessPathNode("권한", targetPermission.getDescription(), targetPermission.getName()));
        return new AccessPathDto(path, false, "해당 권한을 부여하는 경로를 찾을 수 없습니다.");
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
                    String origin = "그룹: " + group.getName() + " / 역할: " + role.getRoleName();
                    role.getRolePermissions().forEach(rp -> permissionOrigins.putIfAbsent(rp.getPermission().getName(), origin));
                });
            });
        } else if ("GROUP".equalsIgnoreCase(subjectType)) {
            Group group = groupRepository.findByIdWithRoles(subjectId)
                    .orElseThrow(() -> new IllegalArgumentException("Group not found with ID: " + subjectId));
            group.getGroupRoles().forEach(gr -> {
                Role role = gr.getRole();
                String origin = "역할: " + role.getRoleName();
                role.getRolePermissions().forEach(rp -> permissionOrigins.putIfAbsent(rp.getPermission().getName(), origin));
            });
        }
        if (permissionOrigins.isEmpty()) return Collections.emptyList();
        return permissionRepository.findAllByNameIn(permissionOrigins.keySet()).stream()
                .map(p -> new EffectivePermissionDto(p.getName(), p.getDescription(), permissionOrigins.get(p.getName())))
                .sorted(Comparator.comparing(EffectivePermissionDto::permissionName))
                .collect(Collectors.toList());
    }

    /**
     * [신규 구현] VirtualSubject에 대한 유효 권한 계산
     */
    @Override
    public List<EffectivePermissionDto> getEffectivePermissionsForSubject(VirtualSubject subject) {
        Map<String, String> permissionOrigins = new HashMap<>();

        subject.getVirtualGroups().forEach(group -> {
            group.getGroupRoles().forEach(gr -> { // groupWithRoles -> group 으로 변경
                Role role = gr.getRole();
                String origin = "그룹: " + group.getName() + " / 역할: " + role.getRoleName();
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