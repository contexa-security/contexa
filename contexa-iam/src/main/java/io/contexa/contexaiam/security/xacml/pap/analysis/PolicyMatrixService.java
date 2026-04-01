package io.contexa.contexaiam.security.xacml.pap.analysis;

import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyMatrixReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyMatrixReport.ConflictCell;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyMatrixReport.MatrixCell;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyMatrixReport.ResourceEntry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Builds a resource x role access matrix showing which roles can access which resources.
 * Reflects role hierarchy inheritance.
 */
@Slf4j
@RequiredArgsConstructor
public class PolicyMatrixService {

    private final PolicyRepository policyRepository;
    private final RoleRepository roleRepository;
    private final RoleHierarchy roleHierarchy;

    private static final Pattern HAS_AUTHORITY_PATTERN = Pattern.compile("hasAuthority\\('([^']*)'\\)");

    /**
     * Generate a resource x role access matrix.
     */
    public PolicyMatrixReport generateMatrix(String resourceFilter, String roleFilter) {
        List<Policy> policies = policyRepository.findAllWithDetails().stream()
                .filter(Policy::getIsActive)
                .toList();

        // Collect all URL resources from policies
        Set<ResourceEntry> resourceEntries = new LinkedHashSet<>();
        for (Policy policy : policies) {
            for (PolicyTarget target : policy.getTargets()) {
                if (!"URL".equals(target.getTargetType())) continue;
                if (resourceFilter != null && !resourceFilter.isBlank()
                        && !target.getTargetIdentifier().contains(resourceFilter)) continue;
                resourceEntries.add(new ResourceEntry(
                        target.getTargetIdentifier(),
                        target.getHttpMethod() != null ? target.getHttpMethod() : "ANY",
                        target.getTargetIdentifier()));
            }
        }

        // Collect all roles
        List<Role> allRoles = roleRepository.findAll().stream()
                .filter(Role::isEnabled)
                .filter(r -> roleFilter == null || roleFilter.isBlank()
                        || r.getRoleName().contains(roleFilter))
                .toList();
        List<String> roleNames = allRoles.stream().map(Role::getRoleName).toList();

        // Build hierarchy map: role -> all reachable roles (including itself)
        Map<String, Set<String>> hierarchyMap = buildHierarchyMap(roleNames);

        // Build matrix
        List<ResourceEntry> resourceList = new ArrayList<>(resourceEntries);
        List<List<MatrixCell>> cells = new ArrayList<>();
        List<ConflictCell> conflictCells = new ArrayList<>();

        for (int row = 0; row < resourceList.size(); row++) {
            ResourceEntry resource = resourceList.get(row);
            List<MatrixCell> rowCells = new ArrayList<>();

            for (int col = 0; col < roleNames.size(); col++) {
                String roleName = roleNames.get(col);
                MatrixCell cell = evaluateCell(resource, roleName, hierarchyMap, policies);
                rowCells.add(cell);

                // Detect conflicts: same resource, opposing effects for same role
                if (cell != null && hasConflictForCell(resource, roleName, hierarchyMap, policies)) {
                    conflictCells.add(new ConflictCell(row, col, "HIGH"));
                }
            }
            cells.add(rowCells);
        }

        return new PolicyMatrixReport(resourceList, roleNames, cells, conflictCells);
    }

    private MatrixCell evaluateCell(ResourceEntry resource, String roleName,
                                     Map<String, Set<String>> hierarchyMap, List<Policy> policies) {
        // Direct match first
        for (Policy policy : policies) {
            if (policyMatchesResource(policy, resource)
                    && policyConditionReferencesRole(policy, roleName)) {
                return new MatrixCell(policy.getEffect().name(),
                        policy.getId(), policy.getName(), false);
            }
        }

        // Inherited match via hierarchy
        Set<String> reachableBy = hierarchyMap.get(roleName);
        if (reachableBy != null) {
            for (String parentRole : reachableBy) {
                if (parentRole.equals(roleName)) continue;
                for (Policy policy : policies) {
                    if (policyMatchesResource(policy, resource)
                            && policyConditionReferencesRole(policy, parentRole)) {
                        return new MatrixCell(policy.getEffect().name(),
                                policy.getId(), policy.getName(), true);
                    }
                }
            }
        }

        return null;
    }

    private boolean hasConflictForCell(ResourceEntry resource, String roleName,
                                       Map<String, Set<String>> hierarchyMap, List<Policy> policies) {
        Set<String> effects = new LinkedHashSet<>();
        Set<String> allRoles = new LinkedHashSet<>();
        allRoles.add(roleName);
        if (hierarchyMap.get(roleName) != null) {
            allRoles.addAll(hierarchyMap.get(roleName));
        }

        for (String role : allRoles) {
            for (Policy policy : policies) {
                if (policyMatchesResource(policy, resource)
                        && policyConditionReferencesRole(policy, role)) {
                    effects.add(policy.getEffect().name());
                }
            }
        }
        return effects.contains("ALLOW") && effects.contains("DENY");
    }

    private boolean policyMatchesResource(Policy policy, ResourceEntry resource) {
        return policy.getTargets().stream()
                .filter(t -> "URL".equals(t.getTargetType()))
                .anyMatch(t -> t.getTargetIdentifier().equals(resource.identifier()));
    }

    private boolean policyConditionReferencesRole(Policy policy, String roleName) {
        for (var rule : policy.getRules()) {
            for (PolicyCondition condition : rule.getConditions()) {
                Matcher matcher = HAS_AUTHORITY_PATTERN.matcher(condition.getExpression());
                while (matcher.find()) {
                    if (matcher.group(1).equals(roleName)) return true;
                }
                if (condition.getExpression().contains("permitAll")) return true;
            }
        }
        return policy.getRules().isEmpty() || policy.getRules().stream()
                .allMatch(r -> r.getConditions().isEmpty());
    }

    private Map<String, Set<String>> buildHierarchyMap(List<String> roleNames) {
        Map<String, Set<String>> map = new LinkedHashMap<>();
        for (String roleName : roleNames) {
            Collection<? extends GrantedAuthority> reachable =
                    roleHierarchy.getReachableGrantedAuthorities(
                            List.of(new SimpleGrantedAuthority(roleName)));
            Set<String> reachableNames = reachable.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            map.put(roleName, reachableNames);
        }
        return map;
    }
}
