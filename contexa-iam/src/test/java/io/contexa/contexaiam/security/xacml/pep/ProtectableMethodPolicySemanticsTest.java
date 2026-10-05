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
package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CompositePermissionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.CustomMethodSecurityExpressionHandler;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.method.MethodPolicyEvaluation;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.pip.context.EnvironmentDetails;
import io.contexa.contexaiam.security.xacml.pip.context.ResourceDetails;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * XACML DENY semantics of {@code @Protectable} method policies evaluated through the real method
 * expression handler and enforcement point.
 */
class ProtectableMethodPolicySemanticsTest {

    private final Authentication anonymous = new AnonymousAuthenticationToken(
            "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    private final Authentication user = UsernamePasswordAuthenticationToken.authenticated(
            "alice", "n/a", AuthorityUtils.createAuthorityList("ROLE_USER"));
    private final Authentication blockedUser = UsernamePasswordAuthenticationToken.authenticated(
            "mallory", "n/a", AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_BLOCKED"));

    private EvaluationContext lastContext;

    private Policy policy(long id, Policy.Effect effect, int priority, String... conditions) {
        Policy policy = Policy.builder().id(id).name("method-policy-" + id).effect(effect).priority(priority)
                .isActive(true).approvalStatus(Policy.ApprovalStatus.APPROVED).build();
        policy.getTargets().add(PolicyTarget.builder().policy(policy).targetType("METHOD")
                .targetIdentifier(OrderService.class.getName() + ".read(Long)").targetOrder(1).build());
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

    private ProtectableMethodAuthorizationManager manager(CombiningAlgorithm algorithm,
                                                          NoPolicyDecision missingPolicyDecision,
                                                          Policy... policies) {
        PolicyRetrievalPoint policyRetrievalPoint = mock(PolicyRetrievalPoint.class);
        when(policyRetrievalPoint.findMethodPolicies(anyString())).thenReturn(List.of(policies));
        ContextHandler contextHandler = mock(ContextHandler.class);
        when(contextHandler.create(any(Authentication.class), any(MethodInvocation.class)))
                .thenAnswer(inv -> new AuthorizationContext(inv.getArgument(0), null,
                        new ResourceDetails("METHOD", "read"), "INVOKE",
                        new EnvironmentDetails("127.0.0.1", LocalDateTime.now(), null), new HashMap<>()));
        PolicyCombiningProperties properties = new PolicyCombiningProperties();
        properties.setCombiningAlgorithm(algorithm);
        properties.setMissingMethodPolicyDecision(missingPolicyDecision);
        CustomMethodSecurityExpressionHandler handler = new CustomMethodSecurityExpressionHandler(
                new SecurityZeroTrustProperties(), mock(CompositePermissionEvaluator.class), new NullRoleHierarchy(),
                policyRetrievalPoint, contextHandler, mock(AuditLogRepository.class),
                mock(ZeroTrustActionRepository.class), properties) {
            @Override
            public EvaluationContext createEvaluationContext(Supplier<Authentication> authentication,
                                                             MethodInvocation mi) {
                lastContext = super.createEvaluationContext(authentication, mi);
                return lastContext;
            }
        };
        return new ProtectableMethodAuthorizationManager(handler, new PolicyCombiningEvaluator());
    }

    private MethodInvocation invocation() throws NoSuchMethodException {
        MethodInvocation invocation = mock(MethodInvocation.class);
        when(invocation.getMethod()).thenReturn(OrderService.class.getMethod("read", Long.class));
        when(invocation.getThis()).thenReturn(new OrderService());
        when(invocation.getArguments()).thenReturn(new Object[]{42L});
        return invocation;
    }

    private boolean granted(ProtectableMethodAuthorizationManager manager, Authentication authentication)
            throws NoSuchMethodException {
        MethodInvocation invocation = invocation();
        try {
            manager.protectable(() -> authentication, invocation);
            return true;
        } catch (AuthorizationDeniedException e) {
            return false;
        }
    }

    @Nested
    @DisplayName("Higher-priority DENY policy followed by an ALLOW policy (FIRST_APPLICABLE)")
    class DenyThenAllow {

        private ProtectableMethodAuthorizationManager firstApplicableManager() {
            return manager(CombiningAlgorithm.FIRST_APPLICABLE, NoPolicyDecision.PERMIT,
                    policy(1L, Policy.Effect.DENY, 10, "hasRole('BLOCKED')"),
                    policy(2L, Policy.Effect.ALLOW, 20, "isAuthenticated()"));
        }

        @Test
        @DisplayName("Anonymous user is denied by the ALLOW policy after the DENY policy does not apply")
        void anonymousUserIsDenied() throws Exception {
            assertThat(granted(firstApplicableManager(), anonymous)).isFalse();
        }

        @Test
        @DisplayName("Authenticated user is permitted")
        void authenticatedUserIsPermitted() throws Exception {
            assertThat(granted(firstApplicableManager(), user)).isTrue();
        }

        @Test
        @DisplayName("User matching the DENY condition is denied")
        void blockedUserIsDenied() throws Exception {
            assertThat(granted(firstApplicableManager(), blockedUser)).isFalse();
        }
    }

    @Nested
    @DisplayName("Only NotApplicable DENY policies")
    class OnlyNotApplicable {

        @ParameterizedTest
        @CsvSource({
                "FIRST_APPLICABLE, PERMIT, true",
                "DENY_OVERRIDES, PERMIT, true",
                "PERMIT_OVERRIDES, PERMIT, true",
                "DENY_UNLESS_PERMIT, PERMIT, false",
                "PERMIT_OVERRIDES, DENY, false",
                "FIRST_APPLICABLE, DENY, false"
        })
        @DisplayName("DENY_UNLESS_PERMIT denies, the other algorithms use the missing-policy decision")
        void notApplicableUsesMissingPolicyDecision(CombiningAlgorithm algorithm, NoPolicyDecision missing,
                                                    boolean expected) throws Exception {
            ProtectableMethodAuthorizationManager manager = manager(algorithm, missing,
                    policy(1L, Policy.Effect.DENY, 10, "hasRole('BLOCKED')"));

            assertThat(granted(manager, user)).isEqualTo(expected);
        }

        @Test
        @DisplayName("Trace marks the unmet DENY policy as not applicable")
        void traceMarksNotApplicable() throws Exception {
            ProtectableMethodAuthorizationManager manager = manager(CombiningAlgorithm.FIRST_APPLICABLE,
                    NoPolicyDecision.PERMIT,
                    policy(1L, Policy.Effect.DENY, 10, "hasRole('BLOCKED')"),
                    policy(2L, Policy.Effect.ALLOW, 20, "isAuthenticated()"));
            MethodInvocation invocation = invocation();

            assertThatCode(() -> manager.protectable(() -> user, invocation)).doesNotThrowAnyException();
            assertThat(trace()).containsExactly(
                    new MethodPolicyEvaluation(1L, Policy.Effect.DENY, 10, false, false),
                    new MethodPolicyEvaluation(2L, Policy.Effect.ALLOW, 20, true, true));
        }
    }

    @Nested
    @DisplayName("Applicable and rejected policies")
    class ApplicableAndRejected {

        @Test
        @DisplayName("DENY policy without conditions always denies")
        void unconditionalDenyAlwaysDenies() throws Exception {
            ProtectableMethodAuthorizationManager manager = manager(CombiningAlgorithm.PERMIT_OVERRIDES,
                    NoPolicyDecision.PERMIT, policy(1L, Policy.Effect.DENY, 10));

            assertThat(granted(manager, user)).isFalse();
        }

        @Test
        @DisplayName("ALLOW policy with a dangerous condition is evaluated as deny")
        void dangerousAllowPolicyDenies() throws Exception {
            ProtectableMethodAuthorizationManager manager = manager(CombiningAlgorithm.FIRST_APPLICABLE,
                    NoPolicyDecision.PERMIT,
                    policy(1L, Policy.Effect.ALLOW, 10, "T(java.lang.Runtime).getRuntime().exec('calc') != null"));

            assertThat(granted(manager, user)).isFalse();
        }

        @Test
        @DisplayName("DENY policy with a dangerous condition is evaluated as deny")
        void dangerousDenyPolicyDenies() throws Exception {
            ProtectableMethodAuthorizationManager manager = manager(CombiningAlgorithm.PERMIT_OVERRIDES,
                    NoPolicyDecision.PERMIT,
                    policy(1L, Policy.Effect.DENY, 10, "@systemSettingsService != null"),
                    policy(2L, Policy.Effect.ALLOW, 20, "isAuthenticated()"));

            assertThat(granted(manager, blockedUser)).isTrue();
            assertThat(granted(manager(CombiningAlgorithm.DENY_OVERRIDES, NoPolicyDecision.PERMIT,
                    policy(1L, Policy.Effect.DENY, 10, "@systemSettingsService != null"),
                    policy(2L, Policy.Effect.ALLOW, 20, "isAuthenticated()")), user)).isFalse();
        }

        @Test
        @DisplayName("Method arguments remain available to policy conditions")
        void methodArgumentsAreAvailable() throws Exception {
            ProtectableMethodAuthorizationManager manager = manager(CombiningAlgorithm.FIRST_APPLICABLE,
                    NoPolicyDecision.DENY, policy(1L, Policy.Effect.ALLOW, 10, "#orderId == 42"));

            assertThat(granted(manager, user)).isTrue();
        }

        @Test
        @DisplayName("Method policy evaluation context rejects reflection at evaluation time")
        void methodPolicyContextIsSandboxed() throws Exception {
            ProtectableMethodAuthorizationManager manager = manager(CombiningAlgorithm.FIRST_APPLICABLE,
                    NoPolicyDecision.PERMIT, policy(1L, Policy.Effect.ALLOW, 10, "isAuthenticated()"));
            MethodInvocation invocation = invocation();
            manager.protectable(() -> user, invocation);

            assertThat(evaluate("#orderId == 42 and hasRole('USER')")).isEqualTo(true);
            assertThatThrownBy(() -> evaluate("#orderId.getClass().forName('java.lang.Runtime')"))
                    .isInstanceOf(RuntimeException.class);
            assertThatThrownBy(() -> evaluate("T(java.lang.Runtime).getRuntime()"))
                    .isInstanceOf(RuntimeException.class);
            assertThatThrownBy(() -> evaluate("new java.lang.ProcessBuilder('calc')"))
                    .isInstanceOf(RuntimeException.class);
        }
    }

    @SuppressWarnings("unchecked")
    private List<MethodPolicyEvaluation> trace() {
        return (List<MethodPolicyEvaluation>) lastContext.lookupVariable("methodPolicyEvaluationTrace");
    }

    private Object evaluate(String expression) {
        return new SpelExpressionParser().parseExpression(expression).getValue(lastContext);
    }

    public static class OrderService {
        public String read(Long orderId) {
            return "order-" + orderId;
        }
    }
}
