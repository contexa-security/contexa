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

import java.util.*;
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
    private static final Pattern HAS_ANY_AUTHORITY_PATTERN = Pattern.compile("hasAnyAuthority\\(([^)]+)\\)");
    private static final Pattern HAS_ROLE_PATTERN = Pattern.compile("hasRole\\('([^']*)'\\)");
    private static final Pattern HAS_ANY_ROLE_PATTERN = Pattern.compile("hasAnyRole\\(([^)]+)\\)");
    private static final Pattern QUOTED_ARG_PATTERN = Pattern.compile("'([^']*)'");

    public PolicyMatrixReport generateMatrix(String resourceFilter, String roleFilter) {
        List<Policy> policies = policyRepository.findAllWithDetails().stream()
                .filter(Policy::getIsActive)
                .toList();

        // Collect all resources (URL + METHOD) from policies
        Set<ResourceEntry> resourceEntries = new LinkedHashSet<>();
        for (Policy policy : policies) {
            for (PolicyTarget target : policy.getTargets()) {
                if (resourceFilter != null && !resourceFilter.isBlank()
                        && !target.getTargetIdentifier().contains(resourceFilter)) continue;
                String method = "METHOD".equals(target.getTargetType()) ? "METHOD"
                        : (target.getHttpMethod() != null ? target.getHttpMethod() : "ANY");
                resourceEntries.add(new ResourceEntry(
                        target.getTargetIdentifier(),
                        method,
                        target.getTargetIdentifier()));
            }
        }

        // Collect all roles with pagination
        List<Role> filteredRoles = roleRepository.findAll().stream()
                .filter(Role::isEnabled)
                .filter(r -> roleFilter == null || roleFilter.isBlank()
                        || r.getRoleName().contains(roleFilter))
                .toList();
        int totalRoles = filteredRoles.size();
        List<String> roleNames = filteredRoles.stream()
                .map(Role::getRoleName).toList();

        // Build hierarchy map
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

                if (cell != null && hasConflictForCell(resource, roleName, hierarchyMap, policies)) {
                    conflictCells.add(new ConflictCell(row, col, "HIGH"));
                }
            }
            cells.add(rowCells);
        }

        return new PolicyMatrixReport(resourceList, roleNames, cells, conflictCells, totalRoles, 1, 0);
    }

    private MatrixCell evaluateCell(ResourceEntry resource, String roleName,
                                     Map<String, Set<String>> hierarchyMap, List<Policy> policies) {
        // Direct match first
        for (Policy policy : policies) {
            if (policyMatchesResource(policy, resource)
                    && policyConditionMatchesRole(policy, roleName)) {
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
                            && policyConditionMatchesRole(policy, parentRole)) {
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
                        && policyConditionMatchesRole(policy, role)) {
                    effects.add(policy.getEffect().name());
                }
            }
        }
        return effects.contains("ALLOW") && effects.contains("DENY");
    }

    private boolean policyMatchesResource(Policy policy, ResourceEntry resource) {
        return policy.getTargets().stream()
                .anyMatch(t -> t.getTargetIdentifier().equals(resource.identifier()));
    }

    /**
     * Checks if a policy's conditions reference or include a specific role.
     * Supports: hasAuthority, hasAnyAuthority, hasRole, hasAnyRole,
     * permitAll, isAuthenticated, and no-condition policies.
     */
    private boolean policyConditionMatchesRole(Policy policy, String roleName) {
        // No rules or all rules have no conditions = unconditional (applies to all roles)
        if (policy.getRules() == null || policy.getRules().isEmpty()) {
            return true;
        }
        boolean hasAnyCondition = false;
        for (var rule : policy.getRules()) {
            if (rule.getConditions() == null || rule.getConditions().isEmpty()) {
                continue;
            }
            for (PolicyCondition condition : rule.getConditions()) {
                hasAnyCondition = true;
                if (expressionMatchesRole(condition.getExpression(), roleName)) {
                    return true;
                }
            }
        }
        return !hasAnyCondition;
    }

    private boolean expressionMatchesRole(String expression, String roleName) {
        if (expression == null || expression.isBlank()) return true;

        // permitAll / isAuthenticated = applies to all roles
        if (expression.contains("permitAll") || expression.contains("isAuthenticated")) return true;

        // AI expressions
        if (expression.contains("#ai.")) return true;

        String roleAuthority = roleName.startsWith("ROLE_") ? roleName : "ROLE_" + roleName;

        // hasAuthority('X')
        Matcher authMatcher = HAS_AUTHORITY_PATTERN.matcher(expression);
        while (authMatcher.find()) {
            String value = authMatcher.group(1);
            if (value.equals(roleName) || value.equals(roleAuthority)) return true;
        }

        // hasAnyAuthority('A', 'B')
        Matcher anyAuthMatcher = HAS_ANY_AUTHORITY_PATTERN.matcher(expression);
        if (anyAuthMatcher.find()) {
            if (matchesAnyQuotedArg(anyAuthMatcher.group(1), roleName)) return true;
        }

        // hasRole('X')
        Matcher roleMatcher = HAS_ROLE_PATTERN.matcher(expression);
        while (roleMatcher.find()) {
            String value = roleMatcher.group(1);
            String fullRole = value.startsWith("ROLE_") ? value : "ROLE_" + value;
            if (fullRole.equals(roleAuthority)) return true;
        }

        // hasAnyRole('A', 'B')
        Matcher anyRoleMatcher = HAS_ANY_ROLE_PATTERN.matcher(expression);
        if (anyRoleMatcher.find()) {
            if (matchesAnyQuotedArgRole(anyRoleMatcher.group(1), roleName)) return true;
        }

        // Plain authority name (e.g. "ROLE_ADMIN" without hasAuthority wrapper)
        if (!expression.contains("(") && !expression.contains(" ")) {
            String trimmed = expression.trim();
            if (trimmed.equals(roleName) || trimmed.equals(roleAuthority)) return true;
        }

        // Compound expression containing role name directly
        if (expression.contains("'" + roleName + "'") || expression.contains("'" + roleAuthority + "'")) {
            return true;
        }

        return false;
    }

    private boolean matchesAnyQuotedArg(String argsString, String roleName) {
        String roleAuthority = roleName.startsWith("ROLE_") ? roleName : "ROLE_" + roleName;
        Matcher argMatcher = QUOTED_ARG_PATTERN.matcher(argsString);
        while (argMatcher.find()) {
            String value = argMatcher.group(1);
            if (value.equals(roleName) || value.equals(roleAuthority)) return true;
        }
        return false;
    }

    private boolean matchesAnyQuotedArgRole(String argsString, String roleName) {
        String roleAuthority = roleName.startsWith("ROLE_") ? roleName : "ROLE_" + roleName;
        Matcher argMatcher = QUOTED_ARG_PATTERN.matcher(argsString);
        while (argMatcher.find()) {
            String value = argMatcher.group(1);
            String fullRole = value.startsWith("ROLE_") ? value : "ROLE_" + value;
            if (fullRole.equals(roleAuthority)) return true;
        }
        return false;
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
