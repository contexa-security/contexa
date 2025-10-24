package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexaiam.domain.entity.RoleHierarchyEntity;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class RoleHierarchyService {

    private final RoleHierarchyRepository roleHierarchyRepository;
    private final RoleRepository roleRepository;
    private final RoleHierarchyImpl roleHierarchy;

    @PostConstruct
    public void initializeRoleHierarchy() {
        log.info("Initializing RoleHierarchyService and setting initial RoleHierarchyImpl hierarchy...");
        reloadRoleHierarchyBean();
    }

    @Cacheable(value = "roleHierarchies", key = "'allRoleHierarchies'")
    public List<RoleHierarchyEntity> getAllRoleHierarchies() {
        return roleHierarchyRepository.findAll();
    }

    @Cacheable(value = "roleHierarchies", key = "#id")
    public Optional<RoleHierarchyEntity> getRoleHierarchy(Long id) {
        return roleHierarchyRepository.findById(id);
    }

    @Cacheable(value = "activeRoleHierarchyString", key = "'current'")
    public String getActiveRoleHierarchyString() {
        return roleHierarchyRepository.findByIsActiveTrue()
                .map(RoleHierarchyEntity::getHierarchyString)
                .orElse("");
    }

    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "roleHierarchies", allEntries = true),
                    @CacheEvict(value = "activeRoleHierarchyString", allEntries = true)
            },
            put = { @CachePut(value = "roleHierarchies", key = "#result.id") }
    )
    public RoleHierarchyEntity createRoleHierarchy(RoleHierarchyEntity roleHierarchyEntity) {
        try {
            log.info("Creating new role hierarchy: {}", roleHierarchyEntity.getDescription());

            if (roleHierarchyRepository.findByHierarchyString(roleHierarchyEntity.getHierarchyString()).isPresent()) {
                throw new IllegalArgumentException("동일한 역할 계층 설정이 이미 존재합니다.");
            }

            // 계층 문자열 유효성 검증 (강화)
            validateHierarchyString(roleHierarchyEntity.getHierarchyString());

            // 순환 참조 및 논리적 오류 검증
            validateHierarchyLogic(roleHierarchyEntity.getHierarchyString());

            RoleHierarchyEntity savedEntity = roleHierarchyRepository.save(roleHierarchyEntity);

            if (savedEntity.getIsActive()) {
                deactivateAllOtherHierarchies(savedEntity.getId());
                reloadRoleHierarchyBean();
            }
            log.info("Created RoleHierarchyEntity with ID: {}", savedEntity.getId());
            return savedEntity;

        } catch (Exception e) {
            log.error("Error creating role hierarchy: ", e);
            throw e;
        }
    }

    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "roleHierarchies", allEntries = true),
                    @CacheEvict(value = "activeRoleHierarchyString", allEntries = true)
            },
            put = { @CachePut(value = "roleHierarchies", key = "#result.id") }
    )
    public RoleHierarchyEntity updateRoleHierarchy(RoleHierarchyEntity roleHierarchyEntity) {
        try {
            log.info("Updating role hierarchy with ID: {}", roleHierarchyEntity.getId());

            RoleHierarchyEntity existingEntity = roleHierarchyRepository.findById(roleHierarchyEntity.getId())
                    .orElseThrow(() -> new IllegalArgumentException("RoleHierarchy not found with ID: " + roleHierarchyEntity.getId()));

            log.info("Validating hierarchy string: {}", roleHierarchyEntity.getHierarchyString());
            validateHierarchyString(roleHierarchyEntity.getHierarchyString());

            log.info("Validating hierarchy logic");
            validateHierarchyLogic(roleHierarchyEntity.getHierarchyString());

            existingEntity.setHierarchyString(roleHierarchyEntity.getHierarchyString());
            existingEntity.setDescription(roleHierarchyEntity.getDescription());
            existingEntity.setIsActive(roleHierarchyEntity.getIsActive());

            RoleHierarchyEntity updatedEntity = roleHierarchyRepository.save(existingEntity);
            log.info("Saved updated entity with ID: {}", updatedEntity.getId());

            if (updatedEntity.getIsActive()) {
                log.info("Deactivating other hierarchies");
                deactivateAllOtherHierarchies(updatedEntity.getId());
            }

            log.info("Reloading role hierarchy bean");
            reloadRoleHierarchyBean();

            log.info("Successfully updated RoleHierarchyEntity with ID: {}", updatedEntity.getId());
            return updatedEntity;

        } catch (Exception e) {
            log.error("Error updating role hierarchy: ", e);
            throw e;
        }
    }

    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "roleHierarchies", allEntries = true),
                    @CacheEvict(value = "activeRoleHierarchyString", allEntries = true),
                    @CacheEvict(value = "roleHierarchies", key = "#id")
            }
    )
    public void deleteRoleHierarchy(Long id) {
        roleHierarchyRepository.deleteById(id);
        reloadRoleHierarchyBean();
        log.info("Deleted RoleHierarchyEntity with ID: {}", id);
    }

    @Transactional
    @CacheEvict(value = "activeRoleHierarchyString", allEntries = true)
    public void activateRoleHierarchy(Long activeId) {
        List<RoleHierarchyEntity> all = roleHierarchyRepository.findAll();
        for (RoleHierarchyEntity entity : all) {
            entity.setIsActive(Objects.equals(entity.getId(), activeId));
            roleHierarchyRepository.save(entity);
        }
        reloadRoleHierarchyBean();
        log.info("Activated RoleHierarchyEntity with ID: {}", activeId);
    }

    public void reloadRoleHierarchyBean() {
        try {
            String hierarchyString = getActiveRoleHierarchyString();

            // DB 에서 읽은 문자열의 \n을 실제 개행문자로 변환
            if (hierarchyString != null && hierarchyString.contains("\\n")) {
                hierarchyString = hierarchyString.replace("\\n", "\n");
                log.debug("Converted \\n to actual newline in hierarchy string");
            }

            roleHierarchy.setHierarchy(hierarchyString);
            log.info("RoleHierarchyImpl bean reloaded with new hierarchy: \n{}", hierarchyString);
        } catch (Exception e) {
            log.error("Failed to reload RoleHierarchyImpl bean dynamically. Error: {}", e.getMessage(), e);
        }
    }

    private void validateHierarchyString(String hierarchyString) {
        if (hierarchyString == null || hierarchyString.trim().isEmpty()) {
            return;
        }

        // \n 문자열을 실제 개행문자로 변환
        if (hierarchyString.contains("\\n")) {
            hierarchyString = hierarchyString.replace("\\n", "\n");
        }

        // 계층 문자열에서 모든 역할 이름 추출
        Set<String> referencedRoleNames = Arrays.stream(hierarchyString.split("[\\r\\n]+"))
                .flatMap(line -> Arrays.stream(line.split("\\s*>\\s*")))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());

        // DB 에서 존재하는 역할명 가져오기 (대소문자 구분 없이)
        Set<String> existingRoleNames = roleRepository.findAll().stream()
                .map(role -> role.getRoleName().toUpperCase())
                .collect(Collectors.toSet());

        log.debug("Referenced roles in hierarchy: {}", referencedRoleNames);
        log.debug("Existing roles in database: {}", existingRoleNames);

        // 참조된 각 역할이 DB에 존재하는지 확인
        for (String roleName : referencedRoleNames) {
            if (!existingRoleNames.contains(roleName.toUpperCase())) {
                throw new IllegalArgumentException("계층 문자열에 존재하지 않는 역할이 포함되어 있습니다: " + roleName);
            }
        }
    }

    /**
     * 역할 계층의 논리적 유효성을 검증합니다.
     * - 순환 참조 검출
     * - 중복 관계 검출
     * - 역방향 관계 검출
     * - 전이적 중복 검출
     */
    private void validateHierarchyLogic(String hierarchyString) {
        if (hierarchyString == null || hierarchyString.trim().isEmpty()) {
            return;
        }

        // 계층 관계를 그래프로 구성
        Map<String, Set<String>> graph = new HashMap<>();
        Set<String> allRoles = new HashSet<>();
        List<String[]> relations = new ArrayList<>();

        // 계층 문자열 파싱
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

        // 중복 관계 검출
        Set<String> seenRelations = new HashSet<>();
        for (String[] relation : relations) {
            String relationKey = relation[0] + ">" + relation[1];
            if (!seenRelations.add(relationKey)) {
                throw new IllegalArgumentException("중복된 관계가 발견되었습니다: " + relationKey);
            }
        }

        // 역방향 관계 검출
        for (String[] relation : relations) {
            String reverseKey = relation[1] + ">" + relation[0];
            if (seenRelations.contains(reverseKey)) {
                throw new IllegalArgumentException("역방향 관계가 발견되었습니다: " + relation[0] + " <-> " + relation[1]);
            }
        }

        // 전이적 중복 검출 (A>B, B>C가 있을 때 A>C는 불필요)
        for (String[] relation : relations) {
            if (isTransitivelyConnected(graph, relation[0], relation[1])) {
                throw new IllegalArgumentException("불필요한 관계입니다: " + relation[0] + " > " + relation[1] +
                        " (이미 다른 경로로 연결되어 있습니다)");
            }
        }

        // 순환 참조 검출 (DFS)
        for (String role : allRoles) {
            if (hasCycle(graph, role, new HashSet<>(), new HashSet<>())) {
                throw new IllegalArgumentException("순환 참조가 발견되었습니다. 역할: " + role);
            }
        }
    }

    /**
     * 전이적 연결 확인 - A에서 B로 가는 다른 경로가 있는지 확인
     */
    private boolean isTransitivelyConnected(Map<String, Set<String>> graph, String start, String end) {
        // 직접 연결을 제외한 임시 그래프 생성
        Map<String, Set<String>> tempGraph = new HashMap<>();
        for (Map.Entry<String, Set<String>> entry : graph.entrySet()) {
            tempGraph.put(entry.getKey(), new HashSet<>(entry.getValue()));
        }

        // 직접 연결 제거
        if (tempGraph.containsKey(start)) {
            tempGraph.get(start).remove(end);
        }

        // BFS로 다른 경로 탐색
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
                        return true; // 다른 경로로 도달 가능
                    }
                    queue.offer(child);
                }
            }
        }

        return false;
    }

    /**
     * DFS를 사용하여 순환 참조를 검출합니다.
     */
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