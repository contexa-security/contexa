package io.contexa.contexaiam.admin.support.visualization.service;

import io.contexa.contexaiam.admin.support.visualization.dto.GraphDataDto;
import io.contexa.contexaiam.domain.entity.*;
import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RequiredArgsConstructor
public class VisualizationServiceImpl implements VisualizationService {

    private final UserRepository userRepository;

    @Override
    public GraphDataDto generatePermissionGraphForUser(Long userId) {
        Users user = userRepository.findByIdWithGroupsRolesAndPermissions(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        List<GraphDataDto.Node> nodes = new ArrayList<>();
        List<GraphDataDto.Edge> edges = new ArrayList<>();

        // User Node
        nodes.add(new GraphDataDto.Node("user_" + user.getId(), user.getName(), "USER", Map.of("email", user.getUsername())));

        for (UserGroup ug : user.getUserGroups()) {
            Group group = ug.getGroup();
            String groupId = "group_" + group.getId();
            // Group Node
            nodes.add(new GraphDataDto.Node(groupId, group.getName(), "GROUP", Map.of("description", group.getDescription())));
            // User -> Group Edge
            edges.add(new GraphDataDto.Edge("user_" + user.getId(), groupId, "소속"));

            for (GroupRole gr : group.getGroupRoles()) {
                Role role = gr.getRole();
                String roleId = "role_" + role.getId();
                // Role Node
                nodes.add(new GraphDataDto.Node(roleId, role.getRoleName(), "ROLE", Map.of("description", role.getRoleDesc())));
                // Group -> Role Edge
                edges.add(new GraphDataDto.Edge(groupId, roleId, "역할 보유"));

                for (RolePermission rp : role.getRolePermissions()) {
                    Permission perm = rp.getPermission();
                    String permId = "perm_" + perm.getId();
                    // Permission Node
                    nodes.add(new GraphDataDto.Node(permId, perm.getDescription(), "PERMISSION", Map.of("name", perm.getName())));
                    // Role -> Permission Edge
                    edges.add(new GraphDataDto.Edge(roleId, permId, "권한 포함"));
                }
            }
        }
        return new GraphDataDto(nodes, edges);
    }
}
