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
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationReport.DecisionDetail;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationReport.SimulationResult;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationReport.SimulationSummary;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationTestCase;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningEvaluator.CombinedDecision;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyEvaluationOrder;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.PolicyExpressionSandbox;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.PolicyExpressionValidator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CustomMethodSecurityExpressionHandler;
import io.contexa.contexaiam.security.xacml.pdp.translator.PolicyExpressionConverter;
import io.contexa.contexaiam.security.xacml.pep.UrlPolicyTargetMatcher;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.MethodExecutor;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.TypedValue;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.DenyAllPermissionEvaluator;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.*;

/**
 * Simulates policy decisions for test cases with the rules of the enforcement points.
 *
 * <p>URL test cases follow the URL enforcement point and method test cases follow the
 * {@code @Protectable} method enforcement point. Both use the same executable policy filter and
 * evaluation order ({@link PolicyEvaluationOrder}), the same condition expression built from the
 * policy rules ({@link PolicyExpressionConverter} for URL policies and
 * {@link CustomMethodSecurityExpressionHandler#buildPolicyCondition(Policy)} for method policies),
 * the same load time rejection of unsafe conditions, the same effect handling
 * ({@link PolicyCombiningEvaluator#applyEffect}) and the same combining evaluator with the combining
 * algorithm and no-matching-policy decisions currently held by {@link PolicyCombiningProperties}.</p>
 *
 * <p>Conditions are evaluated in the policy expression sandbox against a Spring Security expression
 * root that holds the authorities of the simulated user. Facts that exist only for a live request
 * or invocation cannot be simulated: {@code #ai} predicates are treated as satisfied, and a
 * condition that needs request data or method arguments (for example {@code hasIpAddress} or an
 * object level {@code hasPermission}) is treated as not satisfied.</p>
 */
@RequiredArgsConstructor
public class PolicySimulator {

    private static final String METHOD_TARGET = "METHOD";
    private static final String URL_TARGET = "URL";
    private static final String ROLE_PREFIX = "ROLE_";
    private static final SimulatedAiAssessment SIMULATED_AI_ASSESSMENT = new SimulatedAiAssessment();
    private static final MethodResolver SIMULATED_AI_RESOLVER = new SimulatedAiAssessmentResolver();

    /**
     * Order in which the URL policy query of the policy retrieval point returns policies; the URL
     * enforcement point sorts that list stably by priority.
     */
    private static final Comparator<Policy> URL_RETRIEVAL_ORDER = Comparator
            .<Policy>comparingInt(policy -> PolicyEvaluationOrder.lowestTargetOrder(policy, URL_TARGET, null))
            .thenComparingInt(Policy::getPriority);

    private final UserRepository userRepository;
    private final PolicyRepository policyRepository;
    private final RoleHierarchy roleHierarchy;
    private final PolicyCombiningEvaluator combiningEvaluator;
    private final PolicyCombiningProperties combiningProperties;
    private final PolicyExpressionConverter urlExpressionConverter = new PolicyExpressionConverter();
    private final ExpressionParser expressionParser = new SpelExpressionParser();

    /**
     * Simulates every test case against the stored policies and, when a candidate is given, against
     * the stored policies with the candidate applied. A candidate with the id of a stored policy
     * replaces that policy. The candidate is simulated as deployed, regardless of its approval state.
     */
    public SimulationReport simulate(Policy candidatePolicy, List<SimulationTestCase> testCases) {
        List<Policy> storedPolicies = policyRepository.findAllWithDetails();
        List<Policy> candidatePolicies = candidatePolicy != null
                ? withCandidate(storedPolicies, candidatePolicy)
                : storedPolicies;
        CombiningSettings settings = new CombiningSettings(
                combiningProperties.getCombiningAlgorithm(),
                combiningProperties.getNoMatchingUrlPolicyDecision(),
                combiningProperties.getMissingMethodPolicyDecision());

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
            Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                    user.getUsername(), null, expanded);

            DecisionDetail currentResult = evaluate(
                    testCase, authentication, authorityNames, storedPolicies, null, settings);
            DecisionDetail newResult = candidatePolicy != null
                    ? evaluate(testCase, authentication, authorityNames, candidatePolicies, candidatePolicy, settings)
                    : currentResult;

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
                    testCase, user.getUsername(), currentResult, newResult, changed, changeType));
        }

        return new SimulationReport(results,
                new SimulationSummary(unchanged, allowToDeny, denyToAllow, otherChanges));
    }

    private DecisionDetail evaluate(SimulationTestCase testCase, Authentication authentication,
                                    List<String> authorityNames, List<Policy> policies, Policy candidate,
                                    CombiningSettings settings) {
        boolean methodTarget = METHOD_TARGET.equals(testCase.resolvedTargetType());
        List<Policy> matchedPolicies = methodTarget
                ? matchMethodPolicies(policies, candidate, testCase.path())
                : matchUrlPolicies(policies, candidate, testCase.path(), normalizeHttpMethod(testCase.httpMethod()));

        List<AuthorizationDecision> decisions = new ArrayList<>();
        List<String> expressions = new ArrayList<>();
        for (Policy policy : matchedPolicies) {
            PolicyOutcome outcome = methodTarget
                    ? evaluateMethodPolicy(policy, authentication)
                    : evaluateUrlPolicy(policy, authentication);
            decisions.add(outcome.decision());
            expressions.add(outcome.expression());
        }

        NoPolicyDecision noPolicyDecision = methodTarget ? settings.missingMethodPolicyDecision()
                : settings.noMatchingUrlPolicyDecision();
        CombinedDecision combined = combiningEvaluator.combine(decisions, settings.algorithm(), noPolicyDecision);
        boolean granted = combined.decision().isGranted();
        int decidingIndex = combined.noPolicyDecisionApplied() ? -1 : decidingIndex(decisions, granted);
        Policy decidingPolicy = decidingIndex >= 0 ? matchedPolicies.get(decidingIndex) : null;

        return new DecisionDetail(
                granted ? "ALLOW" : "DENY",
                decidingPolicy != null ? decidingPolicy.getId() : null,
                decidingPolicy != null ? decidingPolicy.getName() : null,
                decidingPolicy != null ? expressions.get(decidingIndex) : null,
                authorityNames,
                combined.algorithm().name(),
                combined.noPolicyDecision().name(),
                combined.noPolicyDecisionApplied());
    }

    /**
     * Selects URL policies like the URL enforcement point: executable policies with a URL target,
     * in the retrieval order sorted stably by priority, whose URL target matches the request.
     */
    private List<Policy> matchUrlPolicies(List<Policy> policies, Policy candidate, String path, String httpMethod) {
        return policies.stream()
                .filter(policy -> policy == candidate || PolicyEvaluationOrder.isExecutable(policy))
                .filter(policy -> policy.getTargets().stream()
                        .anyMatch(target -> URL_TARGET.equals(target.getTargetType())))
                .sorted(URL_RETRIEVAL_ORDER)
                .sorted(PolicyEvaluationOrder.urlOrder())
                .filter(policy -> policy.getTargets().stream()
                        .anyMatch(target -> UrlPolicyTargetMatcher.matches(target, path, httpMethod)))
                .toList();
    }

    /**
     * Selects method policies like the method enforcement point: executable policies bound to the
     * method identifier, in method evaluation order.
     */
    private List<Policy> matchMethodPolicies(List<Policy> policies, Policy candidate, String methodIdentifier) {
        return policies.stream()
                .filter(policy -> policy == candidate || PolicyEvaluationOrder.isExecutable(policy))
                .filter(policy -> policy.getTargets().stream()
                        .anyMatch(target -> METHOD_TARGET.equals(target.getTargetType())
                                && Objects.equals(methodIdentifier, target.getTargetIdentifier())))
                .sorted(PolicyEvaluationOrder.methodOrder(methodIdentifier))
                .toList();
    }

    /**
     * Evaluates a URL policy like the URL enforcement point. A policy whose condition is rejected
     * while loading is a constant Deny there, whatever its effect.
     */
    private PolicyOutcome evaluateUrlPolicy(Policy policy, Authentication authentication) {
        String expression;
        try {
            expression = urlExpressionConverter.toExpression(policy);
        } catch (RuntimeException e) {
            // The enforcement point rejects a policy whose condition cannot be converted.
            return new PolicyOutcome(new AuthorizationDecision(false), null);
        }
        if (urlExpressionConverter.findLoadViolation(policy, expression) != null) {
            return new PolicyOutcome(new AuthorizationDecision(false), expression);
        }
        boolean satisfied = isSatisfied(expression, authentication);
        return new PolicyOutcome(PolicyCombiningEvaluator.applyEffect(policy.getEffect(), satisfied), expression);
    }

    /**
     * Evaluates a method policy like the method enforcement point. A rejected condition is replaced
     * by the constant condition that yields Deny for the policy effect.
     */
    private PolicyOutcome evaluateMethodPolicy(Policy policy, Authentication authentication) {
        String condition = CustomMethodSecurityExpressionHandler.buildPolicyCondition(policy);
        String evaluatedCondition = PolicyExpressionValidator.findViolation(condition).isPresent()
                ? CustomMethodSecurityExpressionHandler.rejectedPolicyCondition(policy)
                : condition;
        boolean satisfied = isSatisfied(evaluatedCondition, authentication);
        return new PolicyOutcome(PolicyCombiningEvaluator.applyEffect(policy.getEffect(), satisfied), condition);
    }

    private boolean isSatisfied(String expression, Authentication authentication) {
        SimulationExpressionRoot root = new SimulationExpressionRoot(authentication);
        root.setRoleHierarchy(roleHierarchy);
        root.setDefaultRolePrefix(ROLE_PREFIX);
        root.setTrustResolver(new AuthenticationTrustResolverImpl());
        root.setPermissionEvaluator(new DenyAllPermissionEvaluator());
        StandardEvaluationContext context = new StandardEvaluationContext(root);
        PolicyExpressionSandbox.apply(context);
        context.getMethodResolvers().add(0, SIMULATED_AI_RESOLVER);
        context.setVariable("ai", SIMULATED_AI_ASSESSMENT);
        try {
            return Boolean.TRUE.equals(expressionParser.parseExpression(expression).getValue(context, Boolean.class));
        } catch (RuntimeException e) {
            // The condition needs facts of a live request or invocation, which a simulation does not have.
            return false;
        }
    }

    /**
     * Returns the index of the policy whose decision the combining algorithm returned: the first
     * applicable decision with the combined outcome, or -1 when no applicable decision has it.
     */
    private static int decidingIndex(List<AuthorizationDecision> decisions, boolean granted) {
        for (int index = 0; index < decisions.size(); index++) {
            AuthorizationDecision decision = decisions.get(index);
            if (decision != null && decision.isGranted() == granted) {
                return index;
            }
        }
        return -1;
    }

    private static List<Policy> withCandidate(List<Policy> storedPolicies, Policy candidate) {
        List<Policy> policies = new ArrayList<>();
        policies.add(candidate);
        for (Policy stored : storedPolicies) {
            if (candidate.getId() == null || !candidate.getId().equals(stored.getId())) {
                policies.add(stored);
            }
        }
        return policies;
    }

    private static String normalizeHttpMethod(String httpMethod) {
        return httpMethod != null ? httpMethod.trim().toUpperCase(Locale.ROOT) : null;
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

    private record CombiningSettings(CombiningAlgorithm algorithm,
                                     NoPolicyDecision noMatchingUrlPolicyDecision,
                                     NoPolicyDecision missingMethodPolicyDecision) {
    }

    private record PolicyOutcome(AuthorizationDecision decision, String expression) {
    }

    /**
     * Expression root with the Spring Security operations shared by the URL and method expression
     * roots of the enforcement points.
     */
    private static final class SimulationExpressionRoot extends SecurityExpressionRoot {

        private SimulationExpressionRoot(Authentication authentication) {
            super(authentication);
        }
    }

    /**
     * Stands in for the AI assessment that only exists for a live request or invocation.
     */
    private static final class SimulatedAiAssessment {
    }

    /**
     * Resolves every method called on the simulated AI assessment to a satisfied result.
     */
    private static final class SimulatedAiAssessmentResolver implements MethodResolver {

        private static final TypedValue SATISFIED = new TypedValue(Boolean.TRUE);

        @Override
        public MethodExecutor resolve(EvaluationContext context, Object targetObject, String name,
                                      List<TypeDescriptor> argumentTypes) {
            return targetObject instanceof SimulatedAiAssessment
                    ? (evaluationContext, target, arguments) -> SATISFIED
                    : null;
        }
    }
}
