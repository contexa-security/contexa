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
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacommon.security.authority.RoleAuthority;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorGuard;
import io.contexa.contexaiam.common.ConsoleInput;
import io.contexa.contexaiam.domain.entity.RoleHierarchyEntity;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheConfig;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.context.MessageSource;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import java.util.*;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Slf4j
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
@CacheConfig(cacheManager = "contexaCacheManager")
public class RoleHierarchyService extends AccountAuthoritiesService {

    private final RoleHierarchyRepository roleHierarchyRepository;
    private final RoleRepository roleRepository;
    private final RoleHierarchyImpl roleHierarchy;
    private final MessageSource messageSource;
    private final LastAdministratorGuard lastAdministratorGuard;

    /** The length of the column of a hierarchy's description. */
    private static final int DESCRIPTION_LENGTH = 255;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        reloadRoleHierarchyBean();
    }

    public List<RoleHierarchyEntity> getAllRoleHierarchies() {
        return roleHierarchyRepository.findAll();
    }

    public Optional<RoleHierarchyEntity> getRoleHierarchy(Long id) {
        return roleHierarchyRepository.findById(id);
    }
    @Protectable(verificationRequired = false)
    public Page<RoleHierarchyEntity> searchRoleHierarchies(String keyword, Pageable pageable) {
        if (StringUtils.hasText(keyword)) {
            String likePattern = "%" + keyword.trim().toLowerCase(Locale.ROOT) + "%";
            return roleHierarchyRepository.searchByKeyword(likePattern, pageable);
        }
        return roleHierarchyRepository.findAll(pageable);
    }

    public String getActiveRoleHierarchyString() {
        return getMergedActiveHierarchyString();
    }

    /**
     * Merge all active hierarchy strings into one.
     * Multiple hierarchies can be active simultaneously.
     */
    public String getMergedActiveHierarchyString() {
        List<RoleHierarchyEntity> activeList = roleHierarchyRepository.findAllByIsActiveTrue();
        if (activeList.isEmpty()) return "";
        return activeList.stream()
                .map(RoleHierarchyEntity::getHierarchyString)
                .collect(Collectors.joining("\n"));
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    public RoleHierarchyEntity createRoleHierarchy(RoleHierarchyEntity roleHierarchyEntity) {
        authoritiesChanged();
        String hierarchyString = requiredHierarchy(roleHierarchyEntity.getHierarchyString());
        roleHierarchyEntity.setHierarchyString(hierarchyString);
        roleHierarchyEntity.setDescription(ConsoleInput.required(messageSource, "crud.field.hierarchy.description",
                roleHierarchyEntity.getDescription(), DESCRIPTION_LENGTH));
        if (roleHierarchyEntity.getIsActive() == null) {
            roleHierarchyEntity.setIsActive(false);
        }

        if (roleHierarchyRepository.findByHierarchyString(hierarchyString).isPresent()) {
            throw new IllegalArgumentException(msg("msg.role.hierarchy.duplicate"));
        }

        validateHierarchyString(hierarchyString);

        validateHierarchyLogic(hierarchyString);

        // Refused even when registered as inactive: switching it on later would make the holders administrators at once.
        lastAdministratorGuard.refuseRolesAboveAdministrator(hierarchyString);

        // Validate against existing active hierarchies (even if registering as inactive)
        String currentMerged = getMergedActiveHierarchyString();
        if (!currentMerged.isEmpty()) {
            String candidateMerged = currentMerged + "\n" + hierarchyString;
            validateMergedHierarchy(candidateMerged);
        }

        RoleHierarchyEntity savedEntity = roleHierarchyRepository.save(roleHierarchyEntity);

        if (savedEntity.getIsActive()) {
            reloadRoleHierarchyBean();
        }
        return savedEntity;
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    public RoleHierarchyEntity updateRoleHierarchy(RoleHierarchyEntity roleHierarchyEntity) {
        // First in the transaction: a change of who administers the console waits for the one before it.
        lastAdministratorGuard.serializeChanges();
        List<String> administrators = lastAdministratorGuard.administrators();
        authoritiesChanged();
        RoleHierarchyEntity existingEntity = roleHierarchyRepository.findById(roleHierarchyEntity.getId())
                .orElseThrow(() -> new IllegalArgumentException(
                        msg("msg.role.hierarchy.not.found.id", String.valueOf(roleHierarchyEntity.getId()))));

        String hierarchyString = requiredHierarchy(roleHierarchyEntity.getHierarchyString());
        String description = ConsoleInput.required(messageSource, "crud.field.hierarchy.description",
                roleHierarchyEntity.getDescription(), DESCRIPTION_LENGTH);
        boolean takenByAnother = roleHierarchyRepository.findByHierarchyString(hierarchyString)
                .filter(other -> !Objects.equals(other.getId(), existingEntity.getId()))
                .isPresent();
        if (takenByAnother) {
            throw new IllegalArgumentException(msg("msg.role.hierarchy.duplicate"));
        }

        validateHierarchyString(hierarchyString);

        validateHierarchyLogic(hierarchyString);

        lastAdministratorGuard.refuseRolesAboveAdministrator(hierarchyString);

        existingEntity.setHierarchyString(hierarchyString);
        existingEntity.setDescription(description);
        // A request that does not say whether the hierarchy is in force leaves it as it is.
        if (roleHierarchyEntity.getIsActive() != null) {
            existingEntity.setIsActive(roleHierarchyEntity.getIsActive());
        }

        RoleHierarchyEntity updatedEntity = roleHierarchyRepository.save(existingEntity);

        // Always validate merged hierarchy if any hierarchy is active
        String merged = getMergedActiveHierarchyString();
        if (!merged.isEmpty()) {
            validateMergedHierarchy(merged);
        }

        // Read by the hierarchy the change leaves, before the console runs on it.
        lastAdministratorGuard.refuseLosingEveryAdministrator(administrators, merged);
        reloadRoleHierarchyBean();

        return updatedEntity;
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    public void deleteRoleHierarchy(Long id) {
        lastAdministratorGuard.serializeChanges();
        List<String> administrators = lastAdministratorGuard.administrators();
        authoritiesChanged();
        RoleHierarchyEntity target = roleHierarchyRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException(
                        msg("msg.role.hierarchy.not.found.id", String.valueOf(id))));
        roleHierarchyRepository.delete(target);
        lastAdministratorGuard.refuseLosingEveryAdministrator(administrators, getMergedActiveHierarchyString());
        reloadRoleHierarchyBean();
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    public boolean activateRoleHierarchy(Long activeId) {
        lastAdministratorGuard.serializeChanges();
        List<String> administrators = lastAdministratorGuard.administrators();
        authoritiesChanged();
        RoleHierarchyEntity target = roleHierarchyRepository.findById(activeId)
                .orElseThrow(() -> new IllegalArgumentException(
                        msg("msg.role.hierarchy.not.found.id", String.valueOf(activeId))));

        // Toggle activation
        boolean newState = !Boolean.TRUE.equals(target.getIsActive());

        if (newState) {
            // A hierarchy kept from before the check of ROLE_ADMIN is not switched on with such a relation.
            lastAdministratorGuard.refuseRolesAboveAdministrator(target.getHierarchyString());
            // Validate merged hierarchy with this one added
            String currentMerged = getMergedActiveHierarchyString();
            String candidateMerged = currentMerged.isEmpty()
                    ? target.getHierarchyString()
                    : currentMerged + "\n" + target.getHierarchyString();
            validateMergedHierarchy(candidateMerged);
        }

        target.setIsActive(newState);
        roleHierarchyRepository.save(target);
        lastAdministratorGuard.refuseLosingEveryAdministrator(administrators, getMergedActiveHierarchyString());
        reloadRoleHierarchyBean();
        return newState;
    }

    /**
     * Validate merged hierarchy string for conflicts across multiple active hierarchies.
     * Checks: circular references, reverse relations, duplicate relations.
     */
    public void validateMergedHierarchy(String mergedString) {
        if (mergedString == null || mergedString.trim().isEmpty()) return;
        String normalized = mergedString.replace("\\n", "\n");
        validateHierarchyLogic(normalized);
    }

    public void reloadRoleHierarchyBean() {
        try {
            String hierarchyString = getActiveRoleHierarchyString();

            if (hierarchyString != null && hierarchyString.contains("\\n")) {
                hierarchyString = hierarchyString.replace("\\n", "\n");
            }

            roleHierarchy.setHierarchy(withoutRolesAboveAdministrator(hierarchyString));
        } catch (Exception e) {
            log.error("Failed to reload RoleHierarchyImpl bean dynamically. Error: {}", e.getMessage(), e);
        }
    }

    /**
     * The hierarchy without a relation that places a role above {@code ROLE_ADMIN}. Such a relation is refused when a
     * hierarchy is saved or switched on; one kept from before that check would make the holders of the role above it
     * administrators of the console, so the console does not run on it.
     */
    static String withoutRolesAboveAdministrator(String hierarchyString) {
        if (hierarchyString == null || hierarchyString.isBlank()) {
            return hierarchyString;
        }
        List<String> kept = new ArrayList<>();
        for (String line : hierarchyString.split("\n")) {
            String[] roles = line.split(">");
            boolean aboveAdministrator = Arrays.stream(roles).skip(1)
                    .map(String::trim)
                    .anyMatch(RoleHierarchyService::isAdministratorRole);
            if (aboveAdministrator) {
                log.warn("[RoleHierarchy] A relation that places a role above {} is left out of the hierarchy in force: "
                        + "{}", ConsoleSession.ADMIN_AUTHORITY, line.trim());
                continue;
            }
            kept.add(line);
        }
        return String.join("\n", kept);
    }

    private static boolean isAdministratorRole(String token) {
        return StringUtils.hasText(token)
                && (ConsoleSession.ADMIN_AUTHORITY.equalsIgnoreCase(token)
                || ConsoleSession.ADMIN_AUTHORITY.equalsIgnoreCase(RoleAuthority.authorityOf(token)));
    }

    /** The relations of a hierarchy, refused when there is none. */
    private String requiredHierarchy(String hierarchyString) {
        String value = hierarchyString == null ? "" : hierarchyString.trim();
        if (value.isEmpty() || !value.contains(">")) {
            throw new IllegalArgumentException(msg("msg.role.hierarchy.empty"));
        }
        return value;
    }

    private void validateHierarchyString(String hierarchyString) {
        if (hierarchyString == null || hierarchyString.trim().isEmpty()) {
            return;
        }

        if (hierarchyString.contains("\\n")) {
            hierarchyString = hierarchyString.replace("\\n", "\n");
        }

        Set<String> referencedRoleNames = Arrays.stream(hierarchyString.split("[\\r\\n]+"))
                .flatMap(line -> Arrays.stream(line.split("\\s*>\\s*")))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());

        Set<String> existingRoleNames = roleRepository.findAll().stream()
                .map(role -> role.getRoleName().toUpperCase(Locale.ROOT))
                .collect(Collectors.toSet());

        for (String roleName : referencedRoleNames) {
            if (!existingRoleNames.contains(roleName.toUpperCase(Locale.ROOT))) {
                throw new IllegalArgumentException(msg("msg.role.hierarchy.role.missing", roleName));
            }
        }
    }

    private void validateHierarchyLogic(String hierarchyString) {
        if (hierarchyString == null || hierarchyString.trim().isEmpty()) {
            return;
        }

        Map<String, Set<String>> graph = new HashMap<>();
        Set<String> allRoles = new HashSet<>();
        List<String[]> relations = new ArrayList<>();

        Arrays.stream(hierarchyString.split("\\n"))
                .map(String::trim)
                .filter(s -> s.contains(">"))
                .forEach(relation -> {
                    String[] parts = relation.split(">");
                    if (parts.length == 2) {
                        String parent = parts[0].trim();
                        String child = parts[1].trim();

                        allRoles.add(parent);
                        allRoles.add(child);
                        relations.add(new String[]{parent, child});

                        graph.computeIfAbsent(parent, k -> new HashSet<>()).add(child);
                    }
                });

        Set<String> seenRelations = new HashSet<>();
        for (String[] relation : relations) {
            String relationKey = relation[0] + ">" + relation[1];
            if (!seenRelations.add(relationKey)) {
                throw new IllegalArgumentException(msg("msg.role.hierarchy.duplicate.relation", relationKey));
            }
        }

        for (String[] relation : relations) {
            String reverseKey = relation[1] + ">" + relation[0];
            if (seenRelations.contains(reverseKey)) {
                throw new IllegalArgumentException(msg("msg.role.hierarchy.reverse.relation", relation[0], relation[1]));
            }
        }

        for (String[] relation : relations) {
            if (isTransitivelyConnected(graph, relation[0], relation[1])) {
                throw new IllegalArgumentException(msg("msg.role.hierarchy.redundant", relation[0], relation[1]));
            }
        }

        for (String role : allRoles) {
            if (hasCycle(graph, role, new HashSet<>(), new HashSet<>())) {
                throw new IllegalArgumentException(msg("msg.role.hierarchy.cycle", role));
            }
        }
    }

    private boolean isTransitivelyConnected(Map<String, Set<String>> graph, String start, String end) {

        Map<String, Set<String>> tempGraph = new HashMap<>();
        for (Map.Entry<String, Set<String>> entry : graph.entrySet()) {
            tempGraph.put(entry.getKey(), new HashSet<>(entry.getValue()));
        }

        if (tempGraph.containsKey(start)) {
            tempGraph.get(start).remove(end);
        }

        Queue<String> queue = new LinkedList<>();
        Set<String> visited = new HashSet<>();
        queue.offer(start);

        while (!queue.isEmpty()) {
            String current = queue.poll();
            if (visited.contains(current)) continue;
            visited.add(current);

            Set<String> children = tempGraph.get(current);
            if (children != null) {
                for (String child : children) {
                    if (child.equals(end)) {
                        return true;
                    }
                    queue.offer(child);
                }
            }
        }

        return false;
    }

    private boolean hasCycle(Map<String, Set<String>> graph, String node, Set<String> visited, Set<String> recursionStack) {
        visited.add(node);
        recursionStack.add(node);

        Set<String> children = graph.get(node);
        if (children != null) {
            for (String child : children) {
                if (!visited.contains(child)) {
                    if (hasCycle(graph, child, visited, recursionStack)) {
                        return true;
                    }
                } else if (recursionStack.contains(child)) {
                    return true;
                }
            }
        }

        recursionStack.remove(node);
        return false;
    }

}