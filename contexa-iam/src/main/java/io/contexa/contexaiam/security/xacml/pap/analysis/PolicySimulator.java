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
import io.contexa.contexacommon.security.authority.PermissionAuthority;
import io.contexa.contexacommon.security.authority.RoleAuthority;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationReport.DecisionDetail;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationReport.SimulationResult;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationReport.SimulationSummary;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationTestCase;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.AntPathMatcher;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Simulates policy evaluation for test cases.
 * Evaluates current policies and optionally compares with a candidate policy.
 */
@Slf4j
@RequiredArgsConstructor
public class PolicySimulator {

    private final UserRepository userRepository;
    private final PolicyRepository policyRepository;
    private final RoleHierarchy roleHierarchy;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    private static final Pattern HAS_AUTHORITY_PATTERN = Pattern.compile("hasAuthority\\('([^']*)'\\)");
    private static final Pattern HAS_ANY_AUTHORITY_PATTERN = Pattern.compile("hasAnyAuthority\\(([^)]+)\\)");
    private static final Pattern HAS_ROLE_PATTERN = Pattern.compile("hasRole\\('([^']*)'\\)");
    private static final Pattern HAS_ANY_ROLE_PATTERN = Pattern.compile("hasAnyRole\\(([^)]+)\\)");
    private static final Pattern QUOTED_ARG_PATTERN = Pattern.compile("'([^']*)'");

    public SimulationReport simulate(Policy candidatePolicy, List<SimulationTestCase> testCases) {
        List<Policy> existingPolicies = policyRepository.findAllWithDetails().stream()
                .filter(Policy::getIsActive)
                .sorted(Comparator.comparingInt(Policy::getPriority))
                .toList();

        List<SimulationResult> results = new ArrayList<>();
        int unchanged = 0;
        int allowToDeny = 0;
        int denyToAllow = 0;
        int otherChanges = 0;

        for (SimulationTestCase testCase : testCases) {
            Users user = userRepository.findByIdWithGroupsRolesAndPermissions(testCase.userId()).orElse(null);
            if (user == null) {
                continue;
            }

            Set<GrantedAuthority> baseAuthorities = initializeAuthorities(user);
            Collection<? extends GrantedAuthority> expanded =
                    roleHierarchy.getReachableGrantedAuthorities(baseAuthorities);
            List<String> authorityNames = expanded.stream()
                    .map(GrantedAuthority::getAuthority).toList();

            String targetType = testCase.resolvedTargetType();
            DecisionDetail currentResult = evaluate(
                    targetType, testCase.path(), testCase.httpMethod(), expanded, existingPolicies);

            DecisionDetail newResult;
            if (candidatePolicy != null) {
                List<Policy> withCandidate = new ArrayList<>();
                withCandidate.add(candidatePolicy);
                withCandidate.addAll(existingPolicies);
                newResult = evaluate(
                        targetType, testCase.path(), testCase.httpMethod(), expanded, withCandidate);
            } else {
                newResult = currentResult;
            }

            boolean changed = !currentResult.decision().equals(newResult.decision());
            String changeType = "UNCHANGED";
            if (changed) {
                if ("ALLOW".equals(currentResult.decision()) && "DENY".equals(newResult.decision())) {
                    changeType = "ALLOW_TO_DENY";
                    allowToDeny++;
                } else if (!"ALLOW".equals(currentResult.decision()) && "ALLOW".equals(newResult.decision())) {
                    changeType = "DENY_TO_ALLOW";
                    denyToAllow++;
                } else {
                    changeType = "CHANGED";
                    otherChanges++;
                }
            } else {
                unchanged++;
            }

            results.add(new SimulationResult(
                    testCase, user.getUsername(),
                    new DecisionDetail(currentResult.decision(), currentResult.matchedPolicyId(),
                            currentResult.matchedPolicyName(), currentResult.matchedExpression(), authorityNames),
                    new DecisionDetail(newResult.decision(), newResult.matchedPolicyId(),
                            newResult.matchedPolicyName(), newResult.matchedExpression(), authorityNames),
                    changed, changeType));
        }

        return new SimulationReport(results,
                new SimulationSummary(unchanged, allowToDeny, denyToAllow, otherChanges));
    }

    private DecisionDetail evaluate(String targetType, String identifier, String httpMethod,
                                      Collection<? extends GrantedAuthority> authorities,
                                      List<Policy> policies) {
        Set<String> authorityNames = authorities.stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toSet());

        DecisionDetail firstTargetMatch = null;

        for (Policy policy : policies) {
            boolean targetMatches;
            if ("METHOD".equals(targetType)) {
                targetMatches = policy.getTargets().stream()
                        .filter(t -> "METHOD".equals(t.getTargetType()))
                        .anyMatch(t -> t.getTargetIdentifier().equals(identifier));
            } else {
                targetMatches = policy.getTargets().stream()
                        .filter(t -> "URL".equals(t.getTargetType()))
                        .anyMatch(t -> pathMatches(t.getTargetIdentifier(), identifier)
                                && methodMatches(t.getHttpMethod(), httpMethod));
            }

            if (!targetMatches) continue;

            String expression = policy.getRules().stream()
                    .flatMap(r -> r.getConditions().stream())
                    .map(PolicyCondition::getExpression)
                    .collect(Collectors.joining(" AND "));
            if (expression.isEmpty()) expression = "permitAll";

            boolean conditionMatches = evaluateConditions(policy, authorityNames);
            if (conditionMatches) {
                return new DecisionDetail(
                        policy.getEffect().name(),
                        policy.getId(), policy.getName(),
                        expression, List.of());
            }

            if (firstTargetMatch == null) {
                firstTargetMatch = new DecisionDetail(
                        "DENY", policy.getId(), policy.getName(),
                        expression, List.of());
            }
        }

        return firstTargetMatch != null ? firstTargetMatch
                : new DecisionDetail("NONE", null, null, null, List.of());
    }

    private boolean pathMatches(String pattern, String path) {
        try {
            return pathMatcher.match(pattern, path) || pattern.equals(path);
        } catch (Exception e) {
            return pattern.equals(path);
        }
    }

    private boolean methodMatches(String policyMethod, String requestMethod) {
        if (policyMethod == null || "ANY".equalsIgnoreCase(policyMethod)
                || "ALL".equalsIgnoreCase(policyMethod) || policyMethod.isBlank()) {
            return true;
        }
        return policyMethod.equalsIgnoreCase(requestMethod);
    }

    /**
     * Evaluates conditions of a policy against user authorities.
     * If no rules or no conditions exist, the policy matches unconditionally
     * (same as CustomDynamicAuthorizationManager which converts to permitAll/denyAll).
     */
    private boolean evaluateConditions(Policy policy, Set<String> authorities) {
        if (policy.getRules() == null || policy.getRules().isEmpty()) {
            return true;
        }

        boolean hasAnyCondition = false;
        for (var rule : policy.getRules()) {
            if (rule.getConditions() == null || rule.getConditions().isEmpty()) {
                continue;
            }
            hasAnyCondition = true;
            boolean allMet = true;
            for (PolicyCondition condition : rule.getConditions()) {
                if (!evaluateExpression(condition.getExpression(), authorities)) {
                    allMet = false;
                    break;
                }
            }
            if (allMet) return true;
        }

        // No conditions found in any rule = unconditional match (permitAll equivalent)
        return !hasAnyCondition;
    }

    /**
     * Evaluates a SpEL-like expression against user authorities.
     * Supports all patterns used in the real authorization system.
     */
    private boolean evaluateExpression(String expression, Set<String> authorities) {
        if (expression == null || expression.isBlank()) return true;

        String trimmed = expression.trim();

        // permitAll / isAuthenticated - always true in simulation context
        if (trimmed.contains("permitAll") || trimmed.contains("isAuthenticated")) return true;

        // denyAll - always false
        if (trimmed.equals("denyAll")) return false;

        // AI expressions - treated as true
        if (trimmed.contains("#ai.")) return true;

        // Handle negation: !(expression)
        if (trimmed.startsWith("!(") && trimmed.endsWith(")")) {
            return !evaluateExpression(trimmed.substring(2, trimmed.length() - 1), authorities);
        }

        // Handle OR: (expr1) or (expr2)
        if (trimmed.contains(" or ")) {
            String[] parts = trimmed.split("\\s+or\\s+");
            for (String part : parts) {
                String cleaned = part.trim();
                if (cleaned.startsWith("(") && cleaned.endsWith(")")) {
                    cleaned = cleaned.substring(1, cleaned.length() - 1);
                }
                if (evaluateExpression(cleaned, authorities)) return true;
            }
            return false;
        }

        // Handle AND: expr1 and expr2
        if (trimmed.contains(" and ")) {
            String[] parts = trimmed.split("\\s+and\\s+");
            for (String part : parts) {
                String cleaned = part.trim();
                if (cleaned.startsWith("(") && cleaned.endsWith(")")) {
                    cleaned = cleaned.substring(1, cleaned.length() - 1);
                }
                if (!evaluateExpression(cleaned, authorities)) return false;
            }
            return true;
        }

        // hasAnyAuthority('A', 'B', ...)
        Matcher anyAuthMatcher = HAS_ANY_AUTHORITY_PATTERN.matcher(trimmed);
        if (anyAuthMatcher.find()) {
            return matchesAnyQuotedArg(anyAuthMatcher.group(1), authorities, false);
        }

        // hasAuthority('X')
        Matcher authMatcher = HAS_AUTHORITY_PATTERN.matcher(trimmed);
        if (authMatcher.find()) {
            return authorities.contains(authMatcher.group(1));
        }

        // hasAnyRole('A', 'B', ...)
        Matcher anyRoleMatcher = HAS_ANY_ROLE_PATTERN.matcher(trimmed);
        if (anyRoleMatcher.find()) {
            return matchesAnyQuotedArg(anyRoleMatcher.group(1), authorities, true);
        }

        // hasRole('X')
        Matcher roleMatcher = HAS_ROLE_PATTERN.matcher(trimmed);
        if (roleMatcher.find()) {
            String role = roleMatcher.group(1);
            String fullRole = role.startsWith("ROLE_") ? role : "ROLE_" + role;
            return authorities.contains(fullRole);
        }

        // Plain authority name (used when conditions are just authority names like "ADMIN")
        if (!trimmed.contains("(") && !trimmed.contains(" ")) {
            return authorities.contains(trimmed)
                    || authorities.contains("ROLE_" + trimmed);
        }

        // Unknown expression - cannot evaluate, treat as not matched
        return false;
    }

    /**
     * Extracts quoted arguments and checks if any matches user authorities.
     */
    private boolean matchesAnyQuotedArg(String argsString, Set<String> authorities, boolean isRole) {
        Matcher argMatcher = QUOTED_ARG_PATTERN.matcher(argsString);
        while (argMatcher.find()) {
            String value = argMatcher.group(1);
            if (isRole) {
                String fullRole = value.startsWith("ROLE_") ? value : "ROLE_" + value;
                if (authorities.contains(fullRole)) return true;
            } else {
                if (authorities.contains(value)) return true;
            }
        }
        return false;
    }

    private Set<GrantedAuthority> initializeAuthorities(Users user) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        Optional.ofNullable(user.getUserGroups())
                .orElse(Collections.emptySet()).stream()
                .map(UserGroup::getGroup).filter(Objects::nonNull)
                .flatMap(g -> Optional.ofNullable(g.getGroupRoles())
                        .orElse(Collections.emptySet()).stream())
                .map(GroupRole::getRole).filter(Objects::nonNull).filter(Role::isEnabled)
                .forEach(role -> {
                    authorities.add(new RoleAuthority(role));
                    Optional.ofNullable(role.getRolePermissions())
                            .orElse(Collections.emptySet()).stream()
                            .map(RolePermission::getPermission).filter(Objects::nonNull)
                            .forEach(p -> authorities.add(new PermissionAuthority(p)));
                });

        Optional.ofNullable(user.getUserRoles())
                .orElse(Collections.emptySet()).stream()
                .map(UserRole::getRole).filter(Objects::nonNull).filter(Role::isEnabled)
                .forEach(role -> {
                    authorities.add(new RoleAuthority(role));
                    Optional.ofNullable(role.getRolePermissions())
                            .orElse(Collections.emptySet()).stream()
                            .map(RolePermission::getPermission).filter(Objects::nonNull)
                            .forEach(p -> authorities.add(new PermissionAuthority(p)));
                });

        return authorities;
    }
}
