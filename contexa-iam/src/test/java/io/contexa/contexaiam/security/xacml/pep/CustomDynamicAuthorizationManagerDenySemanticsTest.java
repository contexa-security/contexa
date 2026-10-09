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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.metrics.AuthorizationMetrics;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.AuthenticatedExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.AuthorityExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.CustomWebSecurityExpressionHandler;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.WebSpelExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.pip.context.EnvironmentDetails;
import io.contexa.contexaiam.security.xacml.pip.context.ResourceDetails;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * XACML DENY semantics of URL policies evaluated through the real expression pipeline:
 * a satisfied DENY condition is Deny, an unsatisfied one is NotApplicable.
 */
class CustomDynamicAuthorizationManagerDenySemanticsTest {

    private static final String PATH = "/api/orders/**";
    private static final String REQUEST_PATH = "/api/orders/42";

    private final PolicyRetrievalPoint policyRetrievalPoint = mock(PolicyRetrievalPoint.class);
    private final ContextHandler contextHandler = mock(ContextHandler.class);
    private ExpressionAuthorizationManagerResolver resolver;

    private final Authentication anonymous = new AnonymousAuthenticationToken(
            "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    private final Authentication user = UsernamePasswordAuthenticationToken.authenticated(
            "alice", "n/a", AuthorityUtils.createAuthorityList("ROLE_USER"));
    private final Authentication blockedUser = UsernamePasswordAuthenticationToken.authenticated(
            "mallory", "n/a", AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_BLOCKED"));
    private final Authentication administrator = UsernamePasswordAuthenticationToken.authenticated(
            "root", "n/a", AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
    /** A block replaces every authority with ROLE_BLOCKED (AbstractZeroTrustSecurityService). */
    private final Authentication blockedOnly = UsernamePasswordAuthenticationToken.authenticated(
            "bob", "n/a", AuthorityUtils.createAuthorityList("ROLE_BLOCKED"));

    @BeforeEach
    void setUp() {
        when(contextHandler.create(any(Authentication.class), any(HttpServletRequest.class)))
                .thenAnswer(inv -> new AuthorizationContext(inv.getArgument(0), null,
                        new ResourceDetails("URL", REQUEST_PATH), "GET",
                        new EnvironmentDetails("127.0.0.1", LocalDateTime.now(), inv.getArgument(1)),
                        new HashMap<>()));
        CustomWebSecurityExpressionHandler handler = new CustomWebSecurityExpressionHandler(
                contextHandler, mock(AuditLogRepository.class), mock(ZeroTrustActionRepository.class),
                new NullRoleHierarchy());
        resolver = new ExpressionAuthorizationManagerResolver(List.of(
                new AuthenticatedExpressionEvaluator(),
                new AuthorityExpressionEvaluator(),
                new WebSpelExpressionEvaluator()), handler);
    }

    private Policy policy(long id, Policy.Effect effect, int priority, String path, String... conditions) {
        Policy policy = Policy.builder().id(id).name("policy-" + id).effect(effect).priority(priority)
                .isActive(true).approvalStatus(Policy.ApprovalStatus.APPROVED).build();
        policy.getTargets().add(PolicyTarget.builder()
                .policy(policy).targetType("URL").targetIdentifier(path).httpMethod("ANY").build());
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

    private CustomDynamicAuthorizationManager manager(CombiningAlgorithm algorithm, NoPolicyDecision noMatching,
                                                      Policy... policies) {
        when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of(policies));
        CustomDynamicAuthorizationManager manager = new CustomDynamicAuthorizationManager(
                policyRetrievalPoint, resolver, mock(ObjectMapper.class), contextHandler,
                mock(AuthorizationMetrics.class), mock(CentralAuditFacade.class), new PolicyCombiningEvaluator());
        manager.setCombiningAlgorithm(algorithm);
        manager.setNoMatchingUrlPolicyDecision(noMatching);
        manager.reload();
        return manager;
    }

    private boolean granted(CustomDynamicAuthorizationManager manager, Authentication authentication, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        return manager.check(() -> authentication, new RequestAuthorizationContext(request)).isGranted();
    }

    @Nested
    @DisplayName("Higher-priority DENY policy followed by an ALLOW policy (FIRST_APPLICABLE)")
    class DenyThenAllow {

        private CustomDynamicAuthorizationManager firstApplicableManager() {
            return manager(CombiningAlgorithm.FIRST_APPLICABLE, NoPolicyDecision.PERMIT,
                    policy(1L, Policy.Effect.DENY, 10, PATH, "hasAuthority('ROLE_BLOCKED')"),
                    policy(2L, Policy.Effect.ALLOW, 20, PATH, "isAuthenticated()"));
        }

        @Test
        @DisplayName("Anonymous user is no longer granted by the unmet DENY policy; the ALLOW policy denies")
        void anonymousUserIsDenied() {
            assertThat(granted(firstApplicableManager(), anonymous, REQUEST_PATH)).isFalse();
        }

        @Test
        @DisplayName("Authenticated user falls through the NotApplicable DENY policy to the ALLOW policy")
        void authenticatedUserIsPermitted() {
            assertThat(granted(firstApplicableManager(), user, REQUEST_PATH)).isTrue();
        }

        @Test
        @DisplayName("User matching the DENY condition is denied")
        void blockedUserIsDenied() {
            assertThat(granted(firstApplicableManager(), blockedUser, REQUEST_PATH)).isFalse();
        }
    }

    @Nested
    @DisplayName("Only NotApplicable DENY policies matched")
    class OnlyNotApplicable {

        @ParameterizedTest
        @CsvSource({
                "FIRST_APPLICABLE, true",
                "DENY_OVERRIDES, true",
                "PERMIT_OVERRIDES, true",
                "DENY_UNLESS_PERMIT, false"
        })
        @DisplayName("DENY_UNLESS_PERMIT denies, the other algorithms use the no-matching default (PERMIT)")
        void notApplicableUsesDefaultExceptDenyUnlessPermit(CombiningAlgorithm algorithm, boolean expected) {
            CustomDynamicAuthorizationManager manager = manager(algorithm, NoPolicyDecision.PERMIT,
                    policy(1L, Policy.Effect.DENY, 10, PATH, "hasAuthority('ROLE_BLOCKED')"));

            assertThat(granted(manager, user, REQUEST_PATH)).isEqualTo(expected);
        }

        @ParameterizedTest
        @EnumSource(CombiningAlgorithm.class)
        @DisplayName("No-matching default DENY denies for every algorithm")
        void notApplicableWithDenyDefault(CombiningAlgorithm algorithm) {
            CustomDynamicAuthorizationManager manager = manager(algorithm, NoPolicyDecision.DENY,
                    policy(1L, Policy.Effect.DENY, 10, PATH, "hasAuthority('ROLE_BLOCKED')"));

            assertThat(granted(manager, user, REQUEST_PATH)).isFalse();
        }

        @Test
        @DisplayName("PERMIT_OVERRIDES and DENY_UNLESS_PERMIT now differ when nothing applies")
        void permitOverridesDiffersFromDenyUnlessPermit() {
            Policy denyPolicy = policy(1L, Policy.Effect.DENY, 10, PATH, "hasAuthority('ROLE_BLOCKED')");

            assertThat(granted(manager(CombiningAlgorithm.PERMIT_OVERRIDES, NoPolicyDecision.PERMIT, denyPolicy),
                    user, REQUEST_PATH)).isTrue();
            assertThat(granted(manager(CombiningAlgorithm.DENY_UNLESS_PERMIT, NoPolicyDecision.PERMIT, denyPolicy),
                    user, REQUEST_PATH)).isFalse();
        }

        @Test
        @DisplayName("A request matching no policy keeps the no-matching default even with DENY_UNLESS_PERMIT")
        void noMatchingPolicyUsesDefault() {
            CustomDynamicAuthorizationManager manager = manager(CombiningAlgorithm.DENY_UNLESS_PERMIT,
                    NoPolicyDecision.PERMIT,
                    policy(1L, Policy.Effect.DENY, 10, PATH, "hasAuthority('ROLE_BLOCKED')"));

            assertThat(granted(manager, user, "/public/home")).isTrue();
        }
    }

    @Nested
    @DisplayName("Applicable decisions")
    class ApplicableDecisions {

        @Test
        @DisplayName("DENY policy without conditions always denies")
        void unconditionalDenyAlwaysDenies() {
            CustomDynamicAuthorizationManager manager = manager(CombiningAlgorithm.FIRST_APPLICABLE,
                    NoPolicyDecision.PERMIT, policy(1L, Policy.Effect.DENY, 10, PATH));

            assertThat(granted(manager, user, REQUEST_PATH)).isFalse();
            assertThat(granted(manager, anonymous, REQUEST_PATH)).isFalse();
        }

        @Test
        @DisplayName("Unmet ALLOW policy still denies (unchanged)")
        void unmetAllowDenies() {
            CustomDynamicAuthorizationManager manager = manager(CombiningAlgorithm.PERMIT_OVERRIDES,
                    NoPolicyDecision.PERMIT, policy(1L, Policy.Effect.ALLOW, 10, PATH, "hasAuthority('ROLE_ADMIN')"));

            assertThat(granted(manager, user, REQUEST_PATH)).isFalse();
        }

        @Test
        @DisplayName("Satisfied DENY and ALLOW: DENY_OVERRIDES denies, PERMIT_OVERRIDES permits")
        void satisfiedDenyAndAllow() {
            Policy denyPolicy = policy(1L, Policy.Effect.DENY, 10, PATH, "hasAuthority('ROLE_BLOCKED')");
            Policy allowPolicy = policy(2L, Policy.Effect.ALLOW, 20, PATH, "isAuthenticated()");

            assertThat(granted(manager(CombiningAlgorithm.DENY_OVERRIDES, NoPolicyDecision.PERMIT,
                    denyPolicy, allowPolicy), blockedUser, REQUEST_PATH)).isFalse();
            assertThat(granted(manager(CombiningAlgorithm.PERMIT_OVERRIDES, NoPolicyDecision.PERMIT,
                    denyPolicy, allowPolicy), blockedUser, REQUEST_PATH)).isTrue();
        }
    }

    @Nested
    @DisplayName("Policies rejected while loading")
    class RejectedPolicies {

        @Test
        @DisplayName("ALLOW policy with a dangerous condition denies its targets instead of falling back to PERMIT")
        void dangerousAllowPolicyDeniesTargets() {
            CustomDynamicAuthorizationManager manager = manager(CombiningAlgorithm.FIRST_APPLICABLE,
                    NoPolicyDecision.PERMIT,
                    policy(1L, Policy.Effect.ALLOW, 10, PATH, "T(java.lang.Runtime).getRuntime().exec('calc') != null"));

            assertThat(granted(manager, user, REQUEST_PATH)).isFalse();
            assertThat(granted(manager, user, "/public/home")).isTrue();
        }

        @Test
        @DisplayName("DENY policy with a dangerous condition denies its targets")
        void dangerousDenyPolicyDeniesTargets() {
            CustomDynamicAuthorizationManager manager = manager(CombiningAlgorithm.PERMIT_OVERRIDES,
                    NoPolicyDecision.PERMIT,
                    policy(1L, Policy.Effect.DENY, 10, PATH, "''.getClass().forName('java.lang.Runtime') != null"));

            assertThat(granted(manager, user, REQUEST_PATH)).isFalse();
        }

        @Test
        @DisplayName("Seed policies keep the admin area to administrators and the self-service paths open")
        void seedPoliciesKeepWorking() {
            Policy selfService = policy(3L, Policy.Effect.ALLOW, 20, "/contexa/admin/api/aiam/zero-trust/**",
                    "isAuthenticated()");
            selfService.getTargets().add(PolicyTarget.builder().policy(selfService).targetType("URL")
                    .targetIdentifier("/contexa/admin/api/aiam/sse/zero-trust/**").httpMethod("ANY").build());
            CustomDynamicAuthorizationManager manager = manager(CombiningAlgorithm.FIRST_APPLICABLE,
                    NoPolicyDecision.PERMIT,
                    policy(1L, Policy.Effect.ALLOW, 10, "/contexa/admin/login", "permitAll"),
                    selfService,
                    policy(2L, Policy.Effect.ALLOW, 100, "/contexa/admin/**", "hasRole('ADMIN')"));

            assertThat(granted(manager, anonymous, "/contexa/admin/login")).isTrue();
            assertThat(granted(manager, anonymous, "/contexa/admin/users")).isFalse();
            assertThat(granted(manager, user, "/contexa/admin/users"))
                    .as("a signed-in user without the administrator role stays out of the admin area").isFalse();
            assertThat(granted(manager, administrator, "/contexa/admin/users")).isTrue();
            assertThat(granted(manager, blockedOnly, "/contexa/admin/api/aiam/zero-trust/unblock-request"))
                    .as("a blocked user asks for the release").isTrue();
            assertThat(granted(manager, user, "/contexa/admin/api/aiam/sse/zero-trust/subscribe")).isTrue();
            assertThat(granted(manager, anonymous, "/contexa/admin/api/aiam/zero-trust/unblock-request")).isFalse();
        }
    }
}
