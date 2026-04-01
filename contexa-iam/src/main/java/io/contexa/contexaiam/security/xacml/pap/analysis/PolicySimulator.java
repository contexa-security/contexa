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
 * Simulates policy evaluation for test cases.
 * Compares current policy set results vs results with a candidate policy added.
 */
@Slf4j
@RequiredArgsConstructor
public class PolicySimulator {

    private final UserRepository userRepository;
    private final PolicyRepository policyRepository;
    private final RoleHierarchy roleHierarchy;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private static final Pattern HAS_AUTHORITY_PATTERN = Pattern.compile("hasAuthority\\('([^']*)'\\)");
    private static final Pattern HAS_ROLE_PATTERN = Pattern.compile("hasRole\\('([^']*)'\\)");

    /**
     * Simulate policy evaluation for given test cases.
     *
     * @param candidatePolicy the policy to test (null = evaluate current policies only)
     * @param testCases       list of user/path/method combinations to test
     * @return simulation results comparing current vs new decisions
     */
    public SimulationReport simulate(Policy candidatePolicy, List<SimulationTestCase> testCases) {
        List<Policy> existingPolicies = policyRepository.findAllWithDetails().stream()
                .filter(Policy::getIsActive)
                .toList();

        List<SimulationResult> results = new ArrayList<>();
        int unchanged = 0;
        int allowToDeny = 0;
        int denyToAllow = 0;
        int otherChanges = 0;

        for (SimulationTestCase testCase : testCases) {
            Users user = userRepository.findById(testCase.userId()).orElse(null);
            if (user == null) {
                continue;
            }

            Set<GrantedAuthority> baseAuthorities = initializeAuthorities(user);
            Collection<? extends GrantedAuthority> expanded =
                    roleHierarchy.getReachableGrantedAuthorities(baseAuthorities);
            List<String> authorityNames = expanded.stream()
                    .map(GrantedAuthority::getAuthority).toList();

            DecisionDetail currentResult = evaluateForPath(
                    testCase.path(), testCase.httpMethod(), expanded, existingPolicies);

            DecisionDetail newResult;
            if (candidatePolicy != null) {
                List<Policy> withCandidate = new ArrayList<>();
                withCandidate.add(candidatePolicy);
                withCandidate.addAll(existingPolicies);
                newResult = evaluateForPath(
                        testCase.path(), testCase.httpMethod(), expanded, withCandidate);
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

    private DecisionDetail evaluateForPath(String path, String httpMethod,
                                            Collection<? extends GrantedAuthority> authorities,
                                            List<Policy> policies) {
        Set<String> authorityNames = authorities.stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toSet());

        for (Policy policy : policies) {
            boolean targetMatches = policy.getTargets().stream()
                    .filter(t -> "URL".equals(t.getTargetType()))
                    .anyMatch(t -> pathMatches(t.getTargetIdentifier(), path)
                            && methodMatches(t.getHttpMethod(), httpMethod));

            if (!targetMatches) continue;

            boolean conditionMatches = evaluateConditions(policy, authorityNames);
            if (conditionMatches) {
                String expression = policy.getRules().stream()
                        .flatMap(r -> r.getConditions().stream())
                        .map(PolicyCondition::getExpression)
                        .collect(Collectors.joining(" AND "));

                return new DecisionDetail(
                        policy.getEffect().name(),
                        policy.getId(), policy.getName(),
                        expression, List.of());
            }
        }

        return new DecisionDetail("NONE", null, null, null, List.of());
    }

    private boolean pathMatches(String pattern, String path) {
        try {
            return pathMatcher.match(pattern, path) || pattern.equals(path);
        } catch (Exception e) {
            return pattern.equals(path);
        }
    }

    private boolean methodMatches(String policyMethod, String requestMethod) {
        if (policyMethod == null || "ANY".equalsIgnoreCase(policyMethod) || "ALL".equalsIgnoreCase(policyMethod)) {
            return true;
        }
        return policyMethod.equalsIgnoreCase(requestMethod);
    }

    private boolean evaluateConditions(Policy policy, Set<String> authorities) {
        for (var rule : policy.getRules()) {
            boolean allMet = true;
            for (PolicyCondition condition : rule.getConditions()) {
                if (!evaluateSimpleCondition(condition.getExpression(), authorities)) {
                    allMet = false;
                    break;
                }
            }
            if (allMet) return true;
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
