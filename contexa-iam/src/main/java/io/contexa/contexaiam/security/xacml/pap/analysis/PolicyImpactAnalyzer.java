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
package io.contexa.contexaiam.security.xacml.pap.analysis;

import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.authority.AuthorityResolver;
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

import java.util.*;
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
    private final AuthorityResolver authorityResolver;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    // Support both single quotes and double quotes
    private static final Pattern HAS_AUTHORITY_PATTERN =
            Pattern.compile("hasAuthority\\(['\"]([^'\"]*)['\"]\\)");
    private static final Pattern HAS_ROLE_PATTERN =
            Pattern.compile("hasRole\\(['\"]([^'\"]*)['\"]\\)");

    /**
     * Analyze which users and resources are affected by the candidate policy.
     */
    public PolicyImpactReport analyze(Policy candidatePolicy) {
        Set<String> candidateTargetPaths = candidatePolicy.getTargets().stream()
                .filter(t -> "URL".equals(t.getTargetType()))
                .map(PolicyTarget::getTargetIdentifier)
                .collect(Collectors.toSet());

        if (candidateTargetPaths.isEmpty()) {
            return new PolicyImpactReport(0, List.of(), List.of(), new AccessChangeSummary(0, 0, 0, 0));
        }

        List<Policy> existingPolicies = policyRepository.findAllWithDetails().stream()
                .filter(Policy::getIsActive)
                .toList();

        List<AffectedResource> affectedResources = analyzeAffectedResources(candidatePolicy, existingPolicies);

        // Pre-compute: which existing policies match each candidate target path
        Map<String, List<Policy>> policiesByTarget = new HashMap<>();
        for (String targetPath : candidateTargetPaths) {
            List<Policy> matching = existingPolicies.stream()
                    .filter(p -> policyMatchesTarget(p, targetPath))
                    .toList();
            policiesByTarget.put(targetPath, matching);
        }

        List<Users> allUsers = userRepository.findAll();
        List<AffectedUser> affectedUsers = new ArrayList<>();
        int gained = 0;
        int lost = 0;
        int changed = 0;
        int unchanged = 0;

        for (Users user : allUsers) {
            Set<GrantedAuthority> expandedAuthorities = authorityResolver.resolveAuthorities(user);

            // Per-user: check ALL target paths, determine worst/best change, deduplicate
            String worstChangeType = null;
            String firstCurrentAccess = null;
            String firstNewAccess = null;

            for (String targetPath : candidateTargetPaths) {
                List<Policy> matchingPolicies = policiesByTarget.get(targetPath);
                String currentAccess = evaluateAccess(expandedAuthorities, matchingPolicies);
                String newAccess = evaluateAccessWithCandidate(
                        targetPath, expandedAuthorities, matchingPolicies, candidatePolicy);

                if (!currentAccess.equals(newAccess)) {
                    String changeType;
                    if ("ALLOW".equals(newAccess) && !"ALLOW".equals(currentAccess)) {
                        changeType = "ACCESS_GAINED";
                    } else if (!"ALLOW".equals(newAccess) && "ALLOW".equals(currentAccess)) {
                        changeType = "ACCESS_LOST";
                    } else {
                        changeType = "CHANGED";
                    }
                    // Prioritize: ACCESS_LOST > CHANGED > ACCESS_GAINED
                    if (worstChangeType == null || changeSeverity(changeType) > changeSeverity(worstChangeType)) {
                        worstChangeType = changeType;
                        firstCurrentAccess = currentAccess;
                        firstNewAccess = newAccess;
                    }
                }
            }

            if (worstChangeType != null) {
                // Add user ONCE with the most severe change
                List<String> roleNames = expandedAuthorities.stream()
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
                        firstCurrentAccess, firstNewAccess, worstChangeType));

                if ("ACCESS_GAINED".equals(worstChangeType)) gained++;
                else if ("ACCESS_LOST".equals(worstChangeType)) lost++;
                else changed++;
            } else {
                unchanged++;
            }
        }

        return new PolicyImpactReport(
                affectedUsers.size(), affectedUsers, affectedResources,
                new AccessChangeSummary(gained, lost, changed, unchanged));
    }

    private int changeSeverity(String changeType) {
        return switch (changeType) {
            case "ACCESS_LOST" -> 3;
            case "CHANGED" -> 2;
            case "ACCESS_GAINED" -> 1;
            default -> 0;
        };
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

    /**
     * Evaluate access using pre-filtered matching policies only.
     */
    private String evaluateAccess(Collection<? extends GrantedAuthority> authorities,
                                   List<Policy> matchingPolicies) {
        for (Policy policy : matchingPolicies) {
            if (conditionMatches(policy, authorities)) {
                return policy.getEffect().name();
            }
        }
        return "NONE";
    }

    private String evaluateAccessWithCandidate(String targetPath,
                                                Collection<? extends GrantedAuthority> authorities,
                                                List<Policy> matchingExistingPolicies,
                                                Policy candidate) {
        if (policyMatchesTarget(candidate, targetPath) && conditionMatches(candidate, authorities)) {
            return candidate.getEffect().name();
        }
        return evaluateAccess(authorities, matchingExistingPolicies);
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

        for (var rule : policy.getRules()) {
            boolean allConditionsMet = true;
            for (PolicyCondition condition : rule.getConditions()) {
                if (!evaluateSimpleCondition(condition.getExpression(), authorityNames)) {
                    allConditionsMet = false;
                    break;
                }
            }
            if (allConditionsMet) return true;
        }
        return policy.getRules().isEmpty() || policy.getRules().stream()
                .allMatch(r -> r.getConditions().isEmpty());
    }

    private boolean evaluateSimpleCondition(String expression, Set<String> authorities) {
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
        if (expression.contains("permitAll")) return true;
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

}
