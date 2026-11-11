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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.util.matcher.RequestMatcher;

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
 * The decision for a URL no policy names: a signed-in user by default (AUTHENTICATED), with the requests of the sign-in
 * open to everyone; PERMIT and DENY answer as before, and a policy that names a URL decides it whatever the default.
 */
class CustomDynamicAuthorizationManagerNoMatchDefaultTest {

    private static final String UNNAMED = "/h/secured/data";
    private static final String SIGN_IN = "/api/mfa/config";

    private final PolicyRetrievalPoint policyRetrievalPoint = mock(PolicyRetrievalPoint.class);
    private final ContextHandler contextHandler = mock(ContextHandler.class);
    private ExpressionAuthorizationManagerResolver resolver;

    private final Authentication anonymous = new AnonymousAuthenticationToken(
            "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    private final Authentication user = UsernamePasswordAuthenticationToken.authenticated(
            "alice", "n/a", AuthorityUtils.createAuthorityList("ROLE_USER"));
    private final RequestMatcher signInRequests = request -> SIGN_IN.equals(request.getRequestURI());

    @BeforeEach
    void setUp() {
        when(contextHandler.create(any(Authentication.class), any(HttpServletRequest.class)))
                .thenAnswer(inv -> new AuthorizationContext(inv.getArgument(0), null,
                        new ResourceDetails("URL", UNNAMED), "GET",
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

    @Test
    @DisplayName("Without a choice of the operator a URL no policy names needs a signed-in user")
    void theDefaultNeedsASignedInUser() {
        CustomDynamicAuthorizationManager manager = manager(null, CombiningAlgorithm.FIRST_APPLICABLE);

        assertThat(manager.getNoMatchingUrlPolicyDecision()).isEqualTo(NoPolicyDecision.AUTHENTICATED);
        assertThat(granted(manager, anonymous, UNNAMED)).isFalse();
        assertThat(granted(manager, user, UNNAMED)).isTrue();
    }

    @Test
    @DisplayName("Setting no decision keeps the default")
    void noDecisionKeepsTheDefault() {
        CustomDynamicAuthorizationManager manager = manager(null, CombiningAlgorithm.FIRST_APPLICABLE);
        manager.setNoMatchingUrlPolicyDecision(null);

        assertThat(manager.getNoMatchingUrlPolicyDecision()).isEqualTo(NoPolicyDecision.AUTHENTICATED);
    }

    @Test
    @DisplayName("PERMIT keeps a URL no policy names open to everyone, DENY refuses everyone")
    void theFormerDecisionsAnswerAsBefore() {
        CustomDynamicAuthorizationManager permit = manager(NoPolicyDecision.PERMIT, CombiningAlgorithm.FIRST_APPLICABLE);
        assertThat(granted(permit, anonymous, UNNAMED)).isTrue();
        assertThat(granted(permit, user, UNNAMED)).isTrue();

        CustomDynamicAuthorizationManager deny = manager(NoPolicyDecision.DENY, CombiningAlgorithm.FIRST_APPLICABLE);
        assertThat(granted(deny, anonymous, UNNAMED)).isFalse();
        assertThat(granted(deny, user, UNNAMED)).isFalse();
        assertThat(granted(deny, anonymous, SIGN_IN)).as("DENY refuses the sign-in too, as before").isFalse();
    }

    @Test
    @DisplayName("The requests of the sign-in stay open to someone who is not signed in yet")
    void theSignInStaysOpen() {
        CustomDynamicAuthorizationManager manager = manager(null, CombiningAlgorithm.FIRST_APPLICABLE);

        assertThat(granted(manager, anonymous, SIGN_IN)).isTrue();
        assertThat(granted(manager, user, SIGN_IN)).isTrue();
        assertThat(granted(manager, anonymous, UNNAMED)).isFalse();
    }

    @Test
    @DisplayName("Without the sign-in requests nothing is open to someone who is not signed in")
    void withoutSignInRequestsNothingIsOpen() {
        CustomDynamicAuthorizationManager manager = manager(null, CombiningAlgorithm.FIRST_APPLICABLE);
        manager.setSignInRequests(null);

        assertThat(granted(manager, anonymous, SIGN_IN)).isFalse();
    }

    @ParameterizedTest
    @EnumSource(CombiningAlgorithm.class)
    @DisplayName("A policy that names a URL decides it, whatever the default and the sign-in requests")
    void aNamedUrlIsDecidedByItsPolicy(CombiningAlgorithm algorithm) {
        Policy open = policy(1L, Policy.Effect.ALLOW, 10, "/h/public/**", "permitAll");
        Policy administrators = policy(2L, Policy.Effect.ALLOW, 20, "/h/staff/**", "hasAuthority('ROLE_ADMIN')");
        Policy closedSignIn = policy(3L, Policy.Effect.DENY, 30, SIGN_IN, "permitAll");
        CustomDynamicAuthorizationManager manager = manager(null, algorithm, open, administrators, closedSignIn);

        assertThat(granted(manager, anonymous, "/h/public/info")).isTrue();
        assertThat(granted(manager, anonymous, "/h/staff/report")).isFalse();
        assertThat(granted(manager, user, "/h/staff/report")).isFalse();
        assertThat(granted(manager, anonymous, SIGN_IN)).as("a DENY policy on a sign-in request still refuses it").isFalse();
    }

    @Test
    @DisplayName("A DENY policy whose condition is not met leaves the default to decide, sign-in included")
    void notApplicableFallsBackToTheDefault() {
        Policy blockedOnly = policy(1L, Policy.Effect.DENY, 10, "/**", "hasAuthority('ROLE_BLOCKED')");
        CustomDynamicAuthorizationManager manager = manager(null, CombiningAlgorithm.FIRST_APPLICABLE, blockedOnly);

        assertThat(granted(manager, user, UNNAMED)).isTrue();
        assertThat(granted(manager, anonymous, UNNAMED)).isFalse();
        assertThat(granted(manager, anonymous, SIGN_IN)).isTrue();
    }

    @Test
    @DisplayName("DENY_UNLESS_PERMIT denies a matched URL without a permit, sign-in requests included")
    void denyUnlessPermitIsNotTheDefault() {
        Policy blockedOnly = policy(1L, Policy.Effect.DENY, 10, "/**", "hasAuthority('ROLE_BLOCKED')");
        CustomDynamicAuthorizationManager manager = manager(null, CombiningAlgorithm.DENY_UNLESS_PERMIT, blockedOnly);

        assertThat(granted(manager, user, UNNAMED)).isFalse();
        assertThat(granted(manager, anonymous, SIGN_IN)).isFalse();
    }

    private Policy policy(long id, Policy.Effect effect, int priority, String path, String... conditions) {
        Policy policy = Policy.builder().id(id).name("policy-" + id).effect(effect).priority(priority)
                .isActive(true).approvalStatus(Policy.ApprovalStatus.APPROVED).build();
        policy.getTargets().add(PolicyTarget.builder()
                .policy(policy).targetType("URL").targetIdentifier(path).httpMethod("ANY").build());
        PolicyRule rule = PolicyRule.builder().policy(policy).build();
        Set<PolicyCondition> conditionSet = new HashSet<>();
        for (String condition : conditions) {
            conditionSet.add(PolicyCondition.builder().rule(rule).expression(condition).build());
        }
        rule.setConditions(conditionSet);
        policy.getRules().add(rule);
        return policy;
    }

    /** A manager as Contexa's chain gets it: the decision of the operator, if any, and the requests of the sign-in. */
    private CustomDynamicAuthorizationManager manager(NoPolicyDecision decision, CombiningAlgorithm algorithm,
                                                      Policy... policies) {
        when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of(policies));
        CustomDynamicAuthorizationManager manager = new CustomDynamicAuthorizationManager(
                policyRetrievalPoint, resolver, mock(ObjectMapper.class), contextHandler,
                mock(AuthorizationMetrics.class), mock(CentralAuditFacade.class), new PolicyCombiningEvaluator());
        manager.setCombiningAlgorithm(algorithm);
        if (decision != null) {
            manager.setNoMatchingUrlPolicyDecision(decision);
        }
        manager.setSignInRequests(signInRequests);
        manager.reload();
        return manager;
    }

    private boolean granted(CustomDynamicAuthorizationManager manager, Authentication authentication, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        return manager.check(() -> authentication, new RequestAuthorizationContext(request)).isGranted();
    }
}
