package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.GroupRole;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexaiam.domain.entity.RoleHierarchyEntity;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class GroupServiceImpl implements GroupService {
    private final GroupRepository groupRepository;
    private final RoleRepository roleRepository;
    private final RoleHierarchyRepository roleHierarchyRepository;

    @Transactional
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    public Group createGroup(Group group, List<Long> selectedRoleIds) {
        if (groupRepository.findByName(group.getName()).isPresent()) {
            throw new IllegalArgumentException("Group with name " + group.getName() + " already exists.");
        }

        if (selectedRoleIds != null && !selectedRoleIds.isEmpty()) {
            Set<GroupRole> groupRoles = new HashSet<>();
            for (Long roleId : selectedRoleIds) {
                Role role = roleRepository.findById(roleId)
                        .orElseThrow(() -> new IllegalArgumentException("Role not found with ID: " + roleId));
                groupRoles.add(GroupRole.builder().group(group).role(role).build());
            }
            group.setGroupRoles(groupRoles);
        }

        return groupRepository.save(group);
    }

    public Optional<Group> getGroup(Long id) {
        return groupRepository.findByIdWithRoles(id);
    }

    public List<Group> getAllGroups() {
        return groupRepository.findAllWithRolesAndUsers();
    }

    @Transactional
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    public void deleteGroup(Long id) {
        groupRepository.deleteById(id);
    }

    @Transactional
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    public Group updateGroup(Group group, List<Long> selectedRoleIds) {
        Group existingGroup = groupRepository.findByIdWithRoles(group.getId())
                .orElseThrow(() -> new IllegalArgumentException("Group not found with ID: " + group.getId()));

        existingGroup.setName(group.getName());
        existingGroup.setDescription(group.getDescription());

        Set<Long> desiredRoleIds = selectedRoleIds != null ? new HashSet<>(selectedRoleIds) : new HashSet<>();
        Set<GroupRole> currentGroupRoles = existingGroup.getGroupRoles();

        currentGroupRoles.removeIf(groupRole -> !desiredRoleIds.contains(groupRole.getRole().getId()));

        Set<Long> currentRoleIds = currentGroupRoles.stream()
                .map(gr -> gr.getRole().getId())
                .collect(Collectors.toSet());

        desiredRoleIds.stream()
                .filter(desiredId -> !currentRoleIds.contains(desiredId))
                .forEach(newRoleId -> {
                    Role role = roleRepository.findById(newRoleId)
                            .orElseThrow(() -> new IllegalArgumentException("Role not found with ID: " + newRoleId));
                    currentGroupRoles.add(GroupRole.builder().group(existingGroup).role(role).build());
                });

        return existingGroup;
    }

    @Override
    public List<String> checkHierarchyWarnings(List<Long> roleIds) {
        List<String> warnings = new ArrayList<>();
        if (roleIds == null || roleIds.size() < 2) return warnings;

        // Load role names
        List<Role> roles = roleIds.stream()
                .map(id -> roleRepository.findById(id).orElse(null))
                .filter(Objects::nonNull)
                .toList();
        Set<String> roleNames = roles.stream().map(Role::getRoleName).collect(Collectors.toSet());

        // Build hierarchy graph from all active hierarchies
        Map<String, Set<String>> graph = new HashMap<>();
        roleHierarchyRepository.findAllByIsActiveTrue().forEach(h -> {
            String hs = h.getHierarchyString();
            if (hs == null) return;
            hs = hs.replace("\\n", "\n");
            for (String line : hs.split("[\\r\\n]+")) {
                String[] parts = line.split("\\s*>\\s*");
                if (parts.length == 2) {
                    String parent = parts[0].trim();
                    String child = parts[1].trim();
                    graph.computeIfAbsent(parent, k -> new HashSet<>()).add(child);
                }
            }
        });

        if (graph.isEmpty()) return warnings;

        // Check for redundant roles: if roleA > roleB in hierarchy,
        // and both are in the group, roleB is redundant
        Set<String> warnedChildRoles = new HashSet<>();
        for (Role parentRole : roles) {
            Set<String> reachable = getReachableRoles(graph, parentRole.getRoleName());
            for (Role childRole : roles) {
                if (!parentRole.getId().equals(childRole.getId())
                        && reachable.contains(childRole.getRoleName())
                        && !warnedChildRoles.contains(childRole.getRoleName())) {
                    warnings.add("'" + childRole.getRoleName() + "' is already inherited from '" +
                            parentRole.getRoleName() + "' via hierarchy. It may be redundant in this group.");
                    warnedChildRoles.add(childRole.getRoleName());
                }
            }
        }

        return warnings;
    }

    private Set<String> getReachableRoles(Map<String, Set<String>> graph, String start) {
        Set<String> visited = new HashSet<>();
        Queue<String> queue = new LinkedList<>();
        queue.add(start);
        while (!queue.isEmpty()) {
            String current = queue.poll();
            Set<String> children = graph.getOrDefault(current, Collections.emptySet());
            for (String child : children) {
                if (visited.add(child)) {
                    queue.add(child);
                }
            }
        }
        return visited;
    }
}