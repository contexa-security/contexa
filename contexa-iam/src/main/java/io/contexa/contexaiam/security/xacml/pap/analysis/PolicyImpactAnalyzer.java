package io.contexa.contexaiam.security.xacml.pap.analysis;

import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.authority.PermissionAuthority;
import io.contexa.contexacommon.security.authority.RoleAuthority;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyImpactReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyImpactReport.AccessChangeSummary;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyImpactReport.AffectedResource;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyImpactReport.AffectedUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.AntPathMatcher;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Analyzes the impact of a candidate policy on users and resources.
 * Considers role hierarchy, group-based and direct role assignments.
 */
@Slf4j
@RequiredArgsConstructor
public class PolicyImpactAnalyzer {

    private final UserRepository userRepository;
    private final PolicyRepository policyRepository;
    private final RoleHierarchy roleHierarchy;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private static final Pattern HAS_AUTHORITY_PATTERN = Pattern.compile("hasAuthority\\('([^']*)'\\)");
    private static final Pattern HAS_ROLE_PATTERN = Pattern.compile("hasRole\\('([^']*)'\\)");

    /**
     * Analyze which users and resources are affected by the candidate policy.
     */
    public PolicyImpactReport analyze(Policy candidatePolicy) {
        Set<String> candidateTargetPaths = candidatePolicy.getTargets().stream()
                .filter(t -> "URL".equals(t.getTargetType()))
                .map(PolicyTarget::getTargetIdentifier)
                .collect(Collectors.toSet());

        if (candidateTargetPaths.isEmpty()) {
            return new PolicyImpactReport(0, List.of(), List.of(), new AccessChangeSummary(0, 0, 0));
        }

        // Collect existing policies for the same targets
        List<Policy> existingPolicies = policyRepository.findAllWithDetails().stream()
                .filter(Policy::getIsActive)
                .toList();

        // Analyze affected resources
        List<AffectedResource> affectedResources = analyzeAffectedResources(candidatePolicy, existingPolicies);

        // Analyze affected users
        List<Users> allUsers = userRepository.findAll();
        List<AffectedUser> affectedUsers = new ArrayList<>();
        int gained = 0;
        int lost = 0;
        int unchanged = 0;

        for (Users user : allUsers) {
            Set<GrantedAuthority> baseAuthorities = initializeAuthorities(user);
            Collection<? extends GrantedAuthority> expandedAuthorities =
                    roleHierarchy.getReachableGrantedAuthorities(baseAuthorities);

            boolean userAffected = false;
            for (String targetPath : candidateTargetPaths) {
                String currentAccess = evaluateAccess(targetPath, expandedAuthorities, existingPolicies);
                String newAccess = evaluateAccessWithCandidate(targetPath, expandedAuthorities,
                        existingPolicies, candidatePolicy);

                if (!currentAccess.equals(newAccess)) {
                    userAffected = true;
                    String changeType;
                    if ("ALLOW".equals(newAccess) && !"ALLOW".equals(currentAccess)) {
                        changeType = "ACCESS_GAINED";
                    } else if (!"ALLOW".equals(newAccess) && "ALLOW".equals(currentAccess)) {
                        changeType = "ACCESS_LOST";
                    } else {
                        changeType = "CHANGED";
                    }

                    List<String> roleNames = baseAuthorities.stream()
                            .filter(a -> a instanceof RoleAuthority)
                            .map(GrantedAuthority::getAuthority)
                            .toList();
                    List<String> groupNames = Optional.ofNullable(user.getUserGroups())
                            .orElse(Collections.emptySet()).stream()
                            .map(UserGroup::getGroup)
                            .filter(Objects::nonNull)
                            .map(Group::getName)
                            .toList();

                    affectedUsers.add(new AffectedUser(
                            user.getId(), user.getUsername(), roleNames, groupNames,
                            currentAccess, newAccess, changeType));

                    if ("ACCESS_GAINED".equals(changeType)) gained++;
                    else if ("ACCESS_LOST".equals(changeType)) lost++;
                }
            }
            if (!userAffected) {
                unchanged++;
            }
        }

        return new PolicyImpactReport(
                affectedUsers.size(), affectedUsers, affectedResources,
                new AccessChangeSummary(gained, lost, unchanged));
    }

    private List<AffectedResource> analyzeAffectedResources(Policy candidate, List<Policy> existingPolicies) {
        List<AffectedResource> resources = new ArrayList<>();
        for (PolicyTarget target : candidate.getTargets()) {
            if (!"URL".equals(target.getTargetType())) continue;

            List<String> matchedPolicyNames = existingPolicies.stream()
                    .filter(p -> p.getTargets().stream().anyMatch(t ->
                            "URL".equals(t.getTargetType()) && targetsOverlap(target.getTargetIdentifier(), t.getTargetIdentifier())))
                    .map(Policy::getName)
                    .toList();

            resources.add(new AffectedResource(
                    target.getTargetIdentifier(),
                    target.getHttpMethod() != null ? target.getHttpMethod() : "ANY",
                    matchedPolicyNames.size(),
                    matchedPolicyNames));
        }
        return resources;
    }

    private String evaluateAccess(String targetPath, Collection<? extends GrantedAuthority> authorities,
                                   List<Policy> policies) {
        for (Policy policy : policies) {
            if (policyMatchesTarget(policy, targetPath) && conditionMatches(policy, authorities)) {
                return policy.getEffect().name();
            }
        }
        return "NONE";
    }

    private String evaluateAccessWithCandidate(String targetPath, Collection<? extends GrantedAuthority> authorities,
                                                List<Policy> existingPolicies, Policy candidate) {
        // Candidate first (higher priority for impact analysis)
        if (policyMatchesTarget(candidate, targetPath) && conditionMatches(candidate, authorities)) {
            return candidate.getEffect().name();
        }
        return evaluateAccess(targetPath, authorities, existingPolicies);
    }

    private boolean policyMatchesTarget(Policy policy, String targetPath) {
        return policy.getTargets().stream()
                .filter(t -> "URL".equals(t.getTargetType()))
                .anyMatch(t -> {
                    try {
                        return pathMatcher.match(t.getTargetIdentifier(), targetPath)
                                || pathMatcher.match(targetPath, t.getTargetIdentifier())
                                || t.getTargetIdentifier().equals(targetPath);
                    } catch (Exception e) {
                        return t.getTargetIdentifier().equals(targetPath);
                    }
                });
    }

    private boolean conditionMatches(Policy policy, Collection<? extends GrantedAuthority> authorities) {
        Set<String> authorityNames = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        // Extract required authorities from policy conditions
        for (var rule : policy.getRules()) {
            boolean allConditionsMet = true;
            for (PolicyCondition condition : rule.getConditions()) {
                String expr = condition.getExpression();
                if (!evaluateSimpleCondition(expr, authorityNames)) {
                    allConditionsMet = false;
                    break;
                }
            }
            if (allConditionsMet) return true;
        }
        // No conditions = permitAll/denyAll depending on effect
        return policy.getRules().isEmpty() || policy.getRules().stream()
                .allMatch(r -> r.getConditions().isEmpty());
    }

    private boolean evaluateSimpleCondition(String expression, Set<String> authorities) {
        // Extract authority from hasAuthority('X') or hasRole('X')
        var matcher = HAS_AUTHORITY_PATTERN.matcher(expression);
        while (matcher.find()) {
            if (authorities.contains(matcher.group(1))) return true;
        }
        var roleMatcher = HAS_ROLE_PATTERN.matcher(expression);
        while (roleMatcher.find()) {
            String role = roleMatcher.group(1);
            String fullRole = role.startsWith("ROLE_") ? role : "ROLE_" + role;
            if (authorities.contains(fullRole)) return true;
        }
        // permitAll
        if (expression.contains("permitAll")) return true;
        // AI conditions - assume match for impact analysis
        if (expression.contains("#ai.")) return true;
        return false;
    }

    private boolean targetsOverlap(String path1, String path2) {
        try {
            return pathMatcher.match(path1, path2) || pathMatcher.match(path2, path1) || path1.equals(path2);
        } catch (Exception e) {
            return path1.equals(path2);
        }
    }

    private Set<GrantedAuthority> initializeAuthorities(Users user) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        Optional.ofNullable(user.getUserGroups())
                .orElse(Collections.emptySet()).stream()
                .map(UserGroup::getGroup)
                .filter(Objects::nonNull)
                .flatMap(group -> Optional.ofNullable(group.getGroupRoles())
                        .orElse(Collections.emptySet()).stream())
                .map(GroupRole::getRole)
                .filter(Objects::nonNull)
                .filter(Role::isEnabled)
                .forEach(role -> {
                    authorities.add(new RoleAuthority(role));
                    Optional.ofNullable(role.getRolePermissions())
                            .orElse(Collections.emptySet()).stream()
                            .map(RolePermission::getPermission)
                            .filter(Objects::nonNull)
                            .forEach(p -> authorities.add(new PermissionAuthority(p)));
                });

        Optional.ofNullable(user.getUserRoles())
                .orElse(Collections.emptySet()).stream()
                .map(UserRole::getRole)
                .filter(Objects::nonNull)
                .filter(Role::isEnabled)
                .forEach(role -> {
                    authorities.add(new RoleAuthority(role));
                    Optional.ofNullable(role.getRolePermissions())
                            .orElse(Collections.emptySet()).stream()
                            .map(RolePermission::getPermission)
                            .filter(Objects::nonNull)
                            .forEach(p -> authorities.add(new PermissionAuthority(p)));
                });

        return authorities;
    }
}
