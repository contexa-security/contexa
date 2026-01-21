package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexaiam.domain.entity.RoleHierarchyEntity;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class RoleHierarchyService {

    private final RoleHierarchyRepository roleHierarchyRepository;
    private final RoleRepository roleRepository;
    private final RoleHierarchyImpl roleHierarchy;

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

    public String getActiveRoleHierarchyString() {
        return roleHierarchyRepository.findByIsActiveTrue()
                .map(RoleHierarchyEntity::getHierarchyString)
                .orElse("");
    }

    @Transactional
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    public RoleHierarchyEntity createRoleHierarchy(RoleHierarchyEntity roleHierarchyEntity) {
        try {
            
            if (roleHierarchyRepository.findByHierarchyString(roleHierarchyEntity.getHierarchyString()).isPresent()) {
                throw new IllegalArgumentException("동일한 역할 계층 설정이 이미 존재합니다.");
            }

            validateHierarchyString(roleHierarchyEntity.getHierarchyString());

            validateHierarchyLogic(roleHierarchyEntity.getHierarchyString());

            RoleHierarchyEntity savedEntity = roleHierarchyRepository.save(roleHierarchyEntity);

            if (savedEntity.getIsActive()) {
                deactivateAllOtherHierarchies(savedEntity.getId());
                reloadRoleHierarchyBean();
            }
                        return savedEntity;

        } catch (Exception e) {
            log.error("Error creating role hierarchy: ", e);
            throw e;
        }
    }

    @Transactional
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    public RoleHierarchyEntity updateRoleHierarchy(RoleHierarchyEntity roleHierarchyEntity) {
        try {
            
            RoleHierarchyEntity existingEntity = roleHierarchyRepository.findById(roleHierarchyEntity.getId())
                    .orElseThrow(() -> new IllegalArgumentException("RoleHierarchy not found with ID: " + roleHierarchyEntity.getId()));

                        validateHierarchyString(roleHierarchyEntity.getHierarchyString());

                        validateHierarchyLogic(roleHierarchyEntity.getHierarchyString());

            existingEntity.setHierarchyString(roleHierarchyEntity.getHierarchyString());
            existingEntity.setDescription(roleHierarchyEntity.getDescription());
            existingEntity.setIsActive(roleHierarchyEntity.getIsActive());

            RoleHierarchyEntity updatedEntity = roleHierarchyRepository.save(existingEntity);
            
            if (updatedEntity.getIsActive()) {
                                deactivateAllOtherHierarchies(updatedEntity.getId());
            }

                        reloadRoleHierarchyBean();

                        return updatedEntity;

        } catch (Exception e) {
            log.error("Error updating role hierarchy: ", e);
            throw e;
        }
    }

    @Transactional
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    public void deleteRoleHierarchy(Long id) {
        roleHierarchyRepository.deleteById(id);
        reloadRoleHierarchyBean();
            }

    @Transactional
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    public void activateRoleHierarchy(Long activeId) {
        List<RoleHierarchyEntity> all = roleHierarchyRepository.findAll();
        for (RoleHierarchyEntity entity : all) {
            entity.setIsActive(Objects.equals(entity.getId(), activeId));
            roleHierarchyRepository.save(entity);
        }
        reloadRoleHierarchyBean();
            }

    public void reloadRoleHierarchyBean() {
        try {
            String hierarchyString = getActiveRoleHierarchyString();

            if (hierarchyString != null && hierarchyString.contains("\\n")) {
                hierarchyString = hierarchyString.replace("\\n", "\n");
                            }

            roleHierarchy.setHierarchy(hierarchyString);
                    } catch (Exception e) {
            log.error("Failed to reload RoleHierarchyImpl bean dynamically. Error: {}", e.getMessage(), e);
        }
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
                .map(role -> role.getRoleName().toUpperCase())
                .collect(Collectors.toSet());

        for (String roleName : referencedRoleNames) {
            if (!existingRoleNames.contains(roleName.toUpperCase())) {
                throw new IllegalArgumentException("계층 문자열에 존재하지 않는 역할이 포함되어 있습니다: " + roleName);
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
                throw new IllegalArgumentException("중복된 관계가 발견되었습니다: " + relationKey);
            }
        }

        for (String[] relation : relations) {
            String reverseKey = relation[1] + ">" + relation[0];
            if (seenRelations.contains(reverseKey)) {
                throw new IllegalArgumentException("역방향 관계가 발견되었습니다: " + relation[0] + " <-> " + relation[1]);
            }
        }

        for (String[] relation : relations) {
            if (isTransitivelyConnected(graph, relation[0], relation[1])) {
                throw new IllegalArgumentException("불필요한 관계입니다: " + relation[0] + " > " + relation[1] +
                        " (이미 다른 경로로 연결되어 있습니다)");
            }
        }

        for (String role : allRoles) {
            if (hasCycle(graph, role, new HashSet<>(), new HashSet<>())) {
                throw new IllegalArgumentException("순환 참조가 발견되었습니다. 역할: " + role);
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

    private void deactivateAllOtherHierarchies(Long currentActiveId) {
        roleHierarchyRepository.findByIsActiveTrue()
                .filter(e -> !e.getId().equals(currentActiveId))
                .ifPresent(e -> {
                    e.setIsActive(false);
                    roleHierarchyRepository.save(e);
                });
    }
}