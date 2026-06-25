/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class GroupServiceImpl implements GroupService {
    private final GroupRepository groupRepository;
    private final RoleRepository roleRepository;
    private final RoleHierarchyRepository roleHierarchyRepository;
    private final MessageSource messageSource;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    @Protectable
    public Group createGroup(Group group, List<Long> selectedRoleIds) {
        if (groupRepository.findByName(group.getName()).isPresent()) {
            throw new IllegalArgumentException(msg("msg.group.name.duplicate"));
        }

        if (selectedRoleIds != null && !selectedRoleIds.isEmpty()) {
            List<Role> roles = roleRepository.findAllById(selectedRoleIds);
            if (roles.size() != selectedRoleIds.size()) {
                throw new IllegalArgumentException(msg("msg.role.not.found"));
            }
            Set<GroupRole> groupRoles = roles.stream()
                    .map(role -> GroupRole.builder().group(group).role(role).build())
                    .collect(Collectors.toSet());
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
    @Override
    public Page<Group> searchGroups(String keyword, Pageable pageable) {
        if (StringUtils.hasText(keyword)) {
            String trimmedKeyword = keyword.trim();
            return groupRepository.findByNameContainingIgnoreCaseOrDescriptionContainingIgnoreCase(
                    trimmedKeyword,
                    trimmedKeyword,
                    pageable
            );
        }
        return groupRepository.findAll(pageable);
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    @Protectable
    public void deleteGroup(Long id) {
        groupRepository.deleteById(id);
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    @Protectable
    public Group updateGroup(Group group, List<Long> selectedRoleIds) {
        Group existingGroup = groupRepository.findByIdWithRoles(group.getId())
                .orElseThrow(() -> new IllegalArgumentException("Group not found."));

        existingGroup.setName(group.getName());
        existingGroup.setDescription(group.getDescription());

        Set<Long> desiredRoleIds = selectedRoleIds != null ? new HashSet<>(selectedRoleIds) : new HashSet<>();
        Set<GroupRole> currentGroupRoles = existingGroup.getGroupRoles();

        currentGroupRoles.removeIf(groupRole -> !desiredRoleIds.contains(groupRole.getRole().getId()));

        Set<Long> currentRoleIds = currentGroupRoles.stream()
                .map(gr -> gr.getRole().getId())
                .collect(Collectors.toSet());

        List<Long> newRoleIds = desiredRoleIds.stream()
                .filter(desiredId -> !currentRoleIds.contains(desiredId))
                .toList();

        if (!newRoleIds.isEmpty()) {
            List<Role> newRoles = roleRepository.findAllById(newRoleIds);
            if (newRoles.size() != newRoleIds.size()) {
                throw new IllegalArgumentException(msg("msg.role.not.found"));
            }
            for (Role role : newRoles) {
                currentGroupRoles.add(GroupRole.builder().group(existingGroup).role(role).build());
            }
        }

        return groupRepository.save(existingGroup);
    }

    @Override
    public List<String> checkHierarchyWarnings(List<Long> roleIds) {
        List<String> warnings = new ArrayList<>();
        if (roleIds == null || roleIds.size() < 2) return warnings;

        List<Role> roles = roleRepository.findAllById(roleIds);
        Set<String> roleNames = roles.stream().map(Role::getRoleName).collect(Collectors.toSet());

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
