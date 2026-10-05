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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.entity.GroupRole;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.metrics.AuthorizationMetrics;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationReport.DecisionDetail;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationTestCase;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CompositePermissionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CustomMethodSecurityExpressionHandler;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.AuthenticatedExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.AuthorityExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.CustomWebSecurityExpressionHandler;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.WebSpelExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.ExpressionAuthorizationManagerResolver;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.pip.context.EnvironmentDetails;
import io.contexa.contexaiam.security.xacml.pip.context.ResourceDetails;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import jakarta.servlet.http.HttpServletRequest;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Runs the same policies through the policy simulator and through the URL and method enforcement
 * points, and requires the simulated decision to equal the enforced one.
 */
class PolicySimulatorRuntimeParityTest {

    private static final String URL_PATTERN = "/api/orders/**";
    private static final String REQUEST_PATH = "/api/orders/42";
    private static final String METHOD_IDENTIFIER = OrderService.class.getName() + ".read(Long)";
    private static final Long USER_ID = 1L;
    private static final Long ADMIN_ID = 2L;
    private static final Long BLOCKED_ID = 3L;

    private static final List<UserFixture> USERS = List.of(
            new UserFixture(USER_ID, "alice", List.of("ROLE_USER")),
            new UserFixture(ADMIN_ID, "root", List.of("ROLE_USER", "ROLE_ADMIN")),
            new UserFixture(BLOCKED_ID, "mallory", List.of("ROLE_USER", "ROLE_BLOCKED")));

    private final AtomicLong roleIds = new AtomicLong(100);

    enum TargetKind { URL, METHOD }

    // ---------------------------------------------------------------- policy builders

    private static Policy policy(long id, TargetKind kind, Policy.Effect effect, int priority, String... conditions) {
        Policy policy = Policy.builder().id(id).name("policy-" + id).effect(effect).priority(priority)
                .isActive(true).approvalStatus(Policy.ApprovalStatus.APPROVED).build();
        PolicyTarget target = kind == TargetKind.URL
                ? PolicyTarget.builder().policy(policy).targetType("URL")
                        .targetIdentifier(URL_PATTERN).httpMethod("ANY").build()
                : PolicyTarget.builder().policy(policy).targetType("METHOD")
                        .targetIdentifier(METHOD_IDENTIFIER).targetOrder(1).build();
        policy.getTargets().add(target);
        if (conditions.length > 0) {
            PolicyRule rule = PolicyRule.builder().policy(policy).build();
            Set<PolicyCondition> conditionSet = new HashSet<>();
            for (String condition : conditions) {
                conditionSet.add(PolicyCondition.builder().rule(rule).expression(condition).build());
            }
            rule.setConditions(conditionSet);
            policy.getRules().add(rule);
        }
        return policy;
    }

    private static PolicyCombiningProperties settings(CombiningAlgorithm algorithm, NoPolicyDecision noPolicyDecision) {
        PolicyCombiningProperties properties = new PolicyCombiningProperties();
        properties.setCombiningAlgorithm(algorithm);
        properties.setNoMatchingUrlPolicyDecision(noPolicyDecision);
        properties.setMissingMethodPolicyDecision(noPolicyDecision);
        return properties;
    }

    // ---------------------------------------------------------------- runtime: URL

    private static boolean urlRuntimeGranted(PolicyCombiningProperties settings, List<Policy> policies,
                                             Authentication authentication) {
        ContextHandler contextHandler = mock(ContextHandler.class);
        when(contextHandler.create(any(Authentication.class), any(HttpServletRequest.class)))
                .thenAnswer(inv -> new AuthorizationContext(inv.getArgument(0), null,
                        new ResourceDetails("URL", REQUEST_PATH), "GET",
                        new EnvironmentDetails("127.0.0.1", LocalDateTime.now(), inv.getArgument(1)),
                        new HashMap<>()));
        CustomWebSecurityExpressionHandler handler = new CustomWebSecurityExpressionHandler(
                contextHandler, mock(AuditLogRepository.class), mock(ZeroTrustActionRepository.class),
                new NullRoleHierarchy());
        ExpressionAuthorizationManagerResolver resolver = new ExpressionAuthorizationManagerResolver(List.of(
                new AuthenticatedExpressionEvaluator(),
                new AuthorityExpressionEvaluator(),
                new WebSpelExpressionEvaluator()), handler);
        PolicyRetrievalPoint policyRetrievalPoint = mock(PolicyRetrievalPoint.class);
        when(policyRetrievalPoint.findUrlPolicies()).thenReturn(policies);
        CustomDynamicAuthorizationManager manager = new CustomDynamicAuthorizationManager(
                policyRetrievalPoint, resolver, mock(ObjectMapper.class), contextHandler,
                mock(AuthorizationMetrics.class), mock(CentralAuditFacade.class), new PolicyCombiningEvaluator());
        manager.setCombiningAlgorithm(settings.getCombiningAlgorithm());
        manager.setNoMatchingUrlPolicyDecision(settings.getNoMatchingUrlPolicyDecision());
        manager.reload();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", REQUEST_PATH);
        return manager.check(() -> authentication, new RequestAuthorizationContext(request)).isGranted();
    }

    // ---------------------------------------------------------------- runtime: METHOD

    private static boolean methodRuntimeGranted(PolicyCombiningProperties settings, List<Policy> policies,
                                                Authentication authentication) throws NoSuchMethodException {
        PolicyRetrievalPoint policyRetrievalPoint = mock(PolicyRetrievalPoint.class);
        when(policyRetrievalPoint.findMethodPolicies(anyString())).thenReturn(policies);
        ContextHandler contextHandler = mock(ContextHandler.class);
        when(contextHandler.create(any(Authentication.class), any(MethodInvocation.class)))
                .thenAnswer(inv -> new AuthorizationContext(inv.getArgument(0), null,
                        new ResourceDetails("METHOD", "read"), "INVOKE",
                        new EnvironmentDetails("127.0.0.1", LocalDateTime.now(), null), new HashMap<>()));
        CustomMethodSecurityExpressionHandler handler = new CustomMethodSecurityExpressionHandler(
                new SecurityZeroTrustProperties(), mock(CompositePermissionEvaluator.class), new NullRoleHierarchy(),
                policyRetrievalPoint, contextHandler, mock(AuditLogRepository.class),
                mock(ZeroTrustActionRepository.class), settings);
        ProtectableMethodAuthorizationManager manager =
                new ProtectableMethodAuthorizationManager(handler, new PolicyCombiningEvaluator());
        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(OrderService.class.getMethod("read", Long.class));
        when(invocation.getThis()).thenReturn(new OrderService());
        when(invocation.getArguments()).thenReturn(new Object[]{42L});
        try {
            manager.protectable(() -> authentication, invocation);
            return true;
        } catch (AuthorizationDeniedException e) {
            return false;
        }
    }

    // ---------------------------------------------------------------- simulator

    private PolicySimulator simulator(PolicyCombiningProperties settings, List<Policy> storedPolicies) {
        UserRepository userRepository = mock(UserRepository.class);
        for (UserFixture fixture : USERS) {
            Users user = user(fixture);
            when(userRepository.findByIdWithGroupsRolesAndPermissions(fixture.id())).thenReturn(Optional.of(user));
        }
        PolicyRepository policyRepository = mock(PolicyRepository.class);
        when(policyRepository.findAllWithDetails()).thenReturn(storedPolicies);
        return new PolicySimulator(userRepository, policyRepository, new NullRoleHierarchy(),
                new PolicyCombiningEvaluator(), settings);
    }

    private Users user(UserFixture fixture) {
        Set<GroupRole> groupRoles = new HashSet<>();
        for (String roleName : fixture.roles()) {
            Role role = mock(Role.class);
            when(role.getId()).thenReturn(roleIds.incrementAndGet());
            when(role.getRoleName()).thenReturn(roleName);
            when(role.isEnabled()).thenReturn(true);
            when(role.getRolePermissions()).thenReturn(Collections.emptySet());
            GroupRole groupRole = mock(GroupRole.class);
            when(groupRole.getRole()).thenReturn(role);
            groupRoles.add(groupRole);
        }
        Group group = mock(Group.class);
        when(group.getGroupRoles()).thenReturn(groupRoles);
        UserGroup userGroup = mock(UserGroup.class);
        when(userGroup.getGroup()).thenReturn(group);
        Users user = mock(Users.class);
        when(user.getId()).thenReturn(fixture.id());
        when(user.getUsername()).thenReturn(fixture.username());
        when(user.getUserGroups()).thenReturn(Set.of(userGroup));
        when(user.getUserRoles()).thenReturn(Collections.emptySet());
        return user;
    }

    private static SimulationTestCase testCase(TargetKind kind, Long userId) {
        return kind == TargetKind.URL
                ? new SimulationTestCase(userId, "URL", REQUEST_PATH, "GET")
                : new SimulationTestCase(userId, "METHOD", METHOD_IDENTIFIER, null);
    }

    private DecisionDetail simulate(TargetKind kind, PolicyCombiningProperties settings, List<Policy> policies,
                                    Long userId) {
        return simulator(settings, policies).simulate(null, List.of(testCase(kind, userId)))
                .results().get(0).currentResult();
    }

    private static boolean runtimeGranted(TargetKind kind, PolicyCombiningProperties settings, List<Policy> policies,
                                          UserFixture fixture) throws NoSuchMethodException {
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                fixture.username(), "n/a", AuthorityUtils.createAuthorityList(fixture.roles().toArray(String[]::new)));
        return kind == TargetKind.URL
                ? urlRuntimeGranted(settings, policies, authentication)
                : methodRuntimeGranted(settings, policies, authentication);
    }

    /**
     * Asserts for every user that the simulated decision equals the enforced decision and returns
     * the simulated details keyed by user id order.
     */
    private List<DecisionDetail> assertParity(TargetKind kind, PolicyCombiningProperties settings, List<Policy> policies)
            throws NoSuchMethodException {
        List<DecisionDetail> details = new ArrayList<>();
        for (UserFixture fixture : USERS) {
            DecisionDetail simulated = simulate(kind, settings, policies, fixture.id());
            boolean enforced = runtimeGranted(kind, settings, policies, fixture);
            assertThat(simulated.decision())
                    .as("%s decision for %s", kind, fixture.username())
                    .isEqualTo(enforced ? "ALLOW" : "DENY");
            details.add(simulated);
        }
        return details;
    }

    // ---------------------------------------------------------------- scenarios

    static Stream<Arguments> everyTargetAndAlgorithm() {
        List<Arguments> arguments = new ArrayList<>();
        for (TargetKind kind : TargetKind.values()) {
            for (CombiningAlgorithm algorithm : CombiningAlgorithm.values()) {
                arguments.add(Arguments.of(kind, algorithm));
            }
        }
        return arguments.stream();
    }

    @ParameterizedTest(name = "{0} {1}")
    @MethodSource("everyTargetAndAlgorithm")
    @DisplayName("An unmet DENY policy is NotApplicable and falls through to the ALLOW policy, as enforced")
    void unmetDenyFallsThroughToAllow(TargetKind kind, CombiningAlgorithm algorithm) throws Exception {
        List<Policy> policies = List.of(
                policy(1L, kind, Policy.Effect.DENY, 10, "hasRole('BLOCKED')"),
                policy(2L, kind, Policy.Effect.ALLOW, 20, "isAuthenticated()"));

        List<DecisionDetail> details = assertParity(kind, settings(algorithm, NoPolicyDecision.PERMIT), policies);

        assertThat(details.get(0).decision()).isEqualTo("ALLOW");
        assertThat(details.get(0).matchedPolicyId()).isEqualTo(2L);
        boolean blockedDenied = algorithm == CombiningAlgorithm.FIRST_APPLICABLE
                || algorithm == CombiningAlgorithm.DENY_OVERRIDES;
        assertThat(details.get(2).decision()).isEqualTo(blockedDenied ? "DENY" : "ALLOW");
        assertThat(details.get(2).matchedPolicyId()).isEqualTo(blockedDenied ? 1L : 2L);
    }

    @ParameterizedTest(name = "{0} {1}")
    @MethodSource("everyTargetAndAlgorithm")
    @DisplayName("Only an unmet DENY policy: DENY_UNLESS_PERMIT denies, other algorithms use the default, as enforced")
    void onlyUnmetDenyUsesDefaultExceptDenyUnlessPermit(TargetKind kind, CombiningAlgorithm algorithm)
            throws Exception {
        List<Policy> policies = List.of(policy(1L, kind, Policy.Effect.DENY, 10, "hasRole('BLOCKED')"));

        DecisionDetail user = assertParity(kind, settings(algorithm, NoPolicyDecision.PERMIT), policies).get(0);

        boolean denyUnlessPermit = algorithm == CombiningAlgorithm.DENY_UNLESS_PERMIT;
        assertThat(user.decision()).isEqualTo(denyUnlessPermit ? "DENY" : "ALLOW");
        assertThat(user.noPolicyDecisionApplied()).isEqualTo(!denyUnlessPermit);
        assertThat(user.matchedPolicyId()).isNull();
        assertThat(user.combiningAlgorithm()).isEqualTo(algorithm.name());
        assertThat(user.noPolicyDecision()).isEqualTo("PERMIT");
    }

    @ParameterizedTest(name = "{0} {1}")
    @MethodSource("everyTargetAndAlgorithm")
    @DisplayName("Each algorithm resolves a satisfied ALLOW and a satisfied DENY policy as enforced")
    void algorithmResolvesConflict(TargetKind kind, CombiningAlgorithm algorithm) throws Exception {
        List<Policy> policies = List.of(
                policy(1L, kind, Policy.Effect.ALLOW, 10, "hasRole('USER')"),
                policy(2L, kind, Policy.Effect.DENY, 20, "hasRole('ADMIN')"));

        List<DecisionDetail> details = assertParity(kind, settings(algorithm, NoPolicyDecision.PERMIT), policies);

        boolean adminDenied = algorithm == CombiningAlgorithm.DENY_OVERRIDES;
        assertThat(details.get(1).decision()).isEqualTo(adminDenied ? "DENY" : "ALLOW");
        assertThat(details.get(1).matchedPolicyId()).isEqualTo(adminDenied ? 2L : 1L);
        assertThat(details.get(1).combiningAlgorithm()).isEqualTo(algorithm.name());
    }

    @ParameterizedTest(name = "{0} {1}")
    @MethodSource("everyTargetAndAlgorithm")
    @DisplayName("Without any matching policy the configured default DENY applies, as enforced")
    void noMatchingPolicyUsesDefaultDeny(TargetKind kind, CombiningAlgorithm algorithm) throws Exception {
        DecisionDetail user = assertParity(kind, settings(algorithm, NoPolicyDecision.DENY), List.of()).get(0);

        assertThat(user.decision()).isEqualTo("DENY");
        assertThat(user.noPolicyDecisionApplied()).isTrue();
        assertThat(user.noPolicyDecision()).isEqualTo("DENY");
    }

    @ParameterizedTest(name = "{0} {1}")
    @MethodSource("everyTargetAndAlgorithm")
    @DisplayName("Only NotApplicable DENY policies with the default DENY deny, as enforced")
    void notApplicableWithDefaultDeny(TargetKind kind, CombiningAlgorithm algorithm) throws Exception {
        List<Policy> policies = List.of(policy(1L, kind, Policy.Effect.DENY, 10, "hasRole('BLOCKED')"));

        assertThat(assertParity(kind, settings(algorithm, NoPolicyDecision.DENY), policies).get(0).decision())
                .isEqualTo("DENY");
    }

    @ParameterizedTest
    @EnumSource(TargetKind.class)
    @DisplayName("Conditions of one policy are combined by the runtime of the target type")
    void conditionsAreCombinedLikeTheRuntime(TargetKind kind) throws Exception {
        List<Policy> policies = List.of(
                policy(1L, kind, Policy.Effect.ALLOW, 10, "hasRole('USER')", "hasRole('ADMIN')"));

        List<DecisionDetail> details = assertParity(
                kind, settings(CombiningAlgorithm.FIRST_APPLICABLE, NoPolicyDecision.PERMIT), policies);

        // URL policies combine their conditions with or, method policies with and.
        assertThat(details.get(0).decision()).isEqualTo(kind == TargetKind.URL ? "ALLOW" : "DENY");
        assertThat(details.get(1).decision()).isEqualTo("ALLOW");
    }

    @ParameterizedTest
    @EnumSource(TargetKind.class)
    @DisplayName("Policies are walked in the evaluation order of the runtime of the target type")
    void evaluationOrderFollowsTheRuntime(TargetKind kind) throws Exception {
        Policy allowWithHigherPriority = policy(1L, kind, Policy.Effect.ALLOW, 10, "isAuthenticated()");
        Policy denyWithLowerTargetOrder = policy(2L, kind, Policy.Effect.DENY, 20, "isAuthenticated()");
        allowWithHigherPriority.getTargets().forEach(target -> target.setTargetOrder(5));
        denyWithLowerTargetOrder.getTargets().forEach(target -> target.setTargetOrder(0));

        DecisionDetail user = assertParity(kind, settings(CombiningAlgorithm.FIRST_APPLICABLE, NoPolicyDecision.PERMIT),
                List.of(denyWithLowerTargetOrder, allowWithHigherPriority)).get(0);

        // URL policies are ordered by priority, method policies by target order first.
        assertThat(user.decision()).isEqualTo(kind == TargetKind.URL ? "ALLOW" : "DENY");
    }

    @ParameterizedTest
    @EnumSource(TargetKind.class)
    @DisplayName("Policies that are not approved are not evaluated, as enforced")
    void unapprovedPolicyIsIgnored(TargetKind kind) throws Exception {
        Policy pending = policy(1L, kind, Policy.Effect.DENY, 10, "isAuthenticated()");
        pending.setApprovalStatus(Policy.ApprovalStatus.PENDING);

        DecisionDetail user = assertParity(
                kind, settings(CombiningAlgorithm.FIRST_APPLICABLE, NoPolicyDecision.PERMIT), List.of(pending)).get(0);

        assertThat(user.decision()).isEqualTo("ALLOW");
        assertThat(user.noPolicyDecisionApplied()).isTrue();
    }

    @ParameterizedTest
    @EnumSource(TargetKind.class)
    @DisplayName("A policy with a rejected condition denies whatever its effect, as enforced")
    void rejectedConditionDenies(TargetKind kind) throws Exception {
        List<Policy> policies = List.of(policy(1L, kind, Policy.Effect.ALLOW, 10,
                "T(java.lang.Runtime).getRuntime().availableProcessors() > 0"));

        List<DecisionDetail> details = assertParity(
                kind, settings(CombiningAlgorithm.FIRST_APPLICABLE, NoPolicyDecision.PERMIT), policies);

        assertThat(details).allSatisfy(detail -> assertThat(detail.decision()).isEqualTo("DENY"));
    }

    @Test
    @DisplayName("A URL target restricted to another HTTP method does not match, as enforced")
    void urlTargetWithOtherHttpMethodDoesNotMatch() throws Exception {
        Policy postOnly = policy(1L, TargetKind.URL, Policy.Effect.DENY, 10, "isAuthenticated()");
        postOnly.getTargets().forEach(target -> target.setHttpMethod("POST"));

        DecisionDetail user = assertParity(TargetKind.URL,
                settings(CombiningAlgorithm.FIRST_APPLICABLE, NoPolicyDecision.PERMIT), List.of(postOnly)).get(0);

        assertThat(user.decision()).isEqualTo("ALLOW");
        assertThat(user.noPolicyDecisionApplied()).isTrue();
    }

    @Test
    @DisplayName("A candidate with the id of a stored policy replaces that policy")
    void candidateReplacesStoredPolicy() {
        PolicyCombiningProperties settings = settings(CombiningAlgorithm.DENY_OVERRIDES, NoPolicyDecision.PERMIT);
        Policy stored = policy(1L, TargetKind.URL, Policy.Effect.DENY, 10, "hasRole('USER')");
        Policy candidate = policy(1L, TargetKind.URL, Policy.Effect.ALLOW, 10, "hasRole('USER')");

        var result = simulator(settings, List.of(stored))
                .simulate(candidate, List.of(testCase(TargetKind.URL, USER_ID))).results().get(0);

        assertThat(result.currentResult().decision()).isEqualTo("DENY");
        assertThat(result.newResult().decision()).isEqualTo("ALLOW");
        assertThat(result.changeType()).isEqualTo("DENY_TO_ALLOW");
    }

    private record UserFixture(Long id, String username, List<String> roles) {
    }

    public static class OrderService {
        public String read(Long orderId) {
            return "order-" + orderId;
        }
    }
}
