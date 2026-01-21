package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.GroupRole;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Transactional(readOnly = true)
public class GroupServiceImpl implements GroupService {
    private final GroupRepository groupRepository;
    private final RoleRepository roleRepository;

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
}