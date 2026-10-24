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
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
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
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A1-8 (AG-11c): a delegated agent's request the URL policies grant is evaluated again as the person the agent acts
 * for and refused when that person could not make it; every other request is decided as before.
 */
class CustomDynamicAuthorizationManagerDelegatorTest {

    private static final String REQUEST_PATH = "/api/orders/42";

    private final PolicyRetrievalPoint policyRetrievalPoint = mock(PolicyRetrievalPoint.class);
    private final ContextHandler contextHandler = mock(ContextHandler.class);
    /** The agent signed in with its own account, which holds the analyst role. */
    private final Authentication agent = UsernamePasswordAuthenticationToken.authenticated(
            "report-bot", "n/a", AuthorityUtils.createAuthorityList("ROLE_ANALYST"));
    private final DelegatorAuthoritySource people = delegatorId -> switch (delegatorId) {
        case "alice" -> Optional.of(UsernamePasswordAuthenticationToken.authenticated("alice", "n/a",
                AuthorityUtils.createAuthorityList("ROLE_USER")));
        case "bob" -> Optional.of(UsernamePasswordAuthenticationToken.authenticated("bob", "n/a",
                AuthorityUtils.createAuthorityList("ROLE_ANALYST")));
        default -> Optional.empty();
    };
    private ExpressionAuthorizationManagerResolver resolver;

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

    @Test
    void anAgentActingForAPersonWhoMayNotMakeTheRequestIsRefused() {
        CustomDynamicAuthorizationManager manager = manager(new DelegatorAuthority(people), true);
        MockHttpServletRequest request = request(stamp("alice", true));

        assertThat(manager.check(() -> agent, new RequestAuthorizationContext(request)).isGranted()).isFalse();
        assertThat(request.getAttribute(BridgeRequestAttributes.DELEGATOR_AUTHORITY)).isEqualTo("DENIED");
    }

    @Test
    void anAgentActingForAPersonWhoMayMakeTheRequestIsDecidedAsBefore() {
        CustomDynamicAuthorizationManager manager = manager(new DelegatorAuthority(people), true);
        MockHttpServletRequest request = request(stamp("bob", true));

        assertThat(manager.check(() -> agent, new RequestAuthorizationContext(request)).isGranted()).isTrue();
        assertThat(request.getAttribute(BridgeRequestAttributes.DELEGATOR_AUTHORITY)).isEqualTo("PERMITTED");
    }

    @Test
    void anUnknownDelegatorRefusesAndAMissingSourceOnlyRecords() {
        MockHttpServletRequest unknown = request(stamp("mallory", true));
        assertThat(manager(new DelegatorAuthority(people), true)
                .check(() -> agent, new RequestAuthorizationContext(unknown)).isGranted()).isFalse();
        assertThat(unknown.getAttribute(BridgeRequestAttributes.DELEGATOR_AUTHORITY)).isEqualTo("UNKNOWN");

        MockHttpServletRequest unchecked = request(stamp("alice", true));
        assertThat(manager(new DelegatorAuthority(null), true)
                .check(() -> agent, new RequestAuthorizationContext(unchecked)).isGranted()).isTrue();
        assertThat(unchecked.getAttribute(BridgeRequestAttributes.DELEGATOR_AUTHORITY)).isEqualTo("UNAVAILABLE");
    }

    @Test
    void aRequestAuthenticatedAsTheDelegatorIsNotEvaluatedTwice() {
        Authentication bobsExchangedToken = UsernamePasswordAuthenticationToken.authenticated(
                "bob", "n/a", AuthorityUtils.createAuthorityList("ROLE_ANALYST"));
        MockHttpServletRequest request = request(stamp("bob", true));
        DelegatorAuthoritySource neverAsked = delegatorId -> {
            throw new AssertionError("the delegator is not looked up");
        };

        assertThat(manager(new DelegatorAuthority(neverAsked), true)
                .check(() -> bobsExchangedToken, new RequestAuthorizationContext(request)).isGranted()).isTrue();
        assertThat(request.getAttribute(BridgeRequestAttributes.DELEGATOR_AUTHORITY)).isEqualTo("CARRIED");
    }

    @Test
    void shadowModeRecordsTheRefusalWithoutEnforcingIt() {
        MockHttpServletRequest request = request(stamp("alice", true));

        assertThat(manager(new DelegatorAuthority(people), false)
                .check(() -> agent, new RequestAuthorizationContext(request)).isGranted()).isTrue();
        assertThat(request.getAttribute(BridgeRequestAttributes.DELEGATOR_AUTHORITY)).isEqualTo("DENIED");
    }

    @Test
    void peopleAndAgentsActingOnTheirOwnAreDecidedAsBefore() {
        CustomDynamicAuthorizationManager manager = manager(new DelegatorAuthority(people), true);
        MockHttpServletRequest person = new MockHttpServletRequest("GET", REQUEST_PATH);
        MockHttpServletRequest autonomous = request(stamp("report-bot", false));

        assertThat(manager.check(() -> agent, new RequestAuthorizationContext(person)).isGranted()).isTrue();
        assertThat(manager.check(() -> agent, new RequestAuthorizationContext(autonomous)).isGranted()).isTrue();
        assertThat(person.getAttribute(BridgeRequestAttributes.DELEGATOR_AUTHORITY)).isNull();
        assertThat(autonomous.getAttribute(BridgeRequestAttributes.DELEGATOR_AUTHORITY)).isNull();
    }

    private CustomDynamicAuthorizationManager manager(DelegatorAuthority delegatorAuthority, boolean enforced) {
        Policy policy = Policy.builder().id(1L).name("analysts").effect(Policy.Effect.ALLOW).priority(1)
                .isActive(true).approvalStatus(Policy.ApprovalStatus.APPROVED).build();
        policy.getTargets().add(PolicyTarget.builder()
                .policy(policy).targetType("URL").targetIdentifier("/api/orders/**").httpMethod("ANY").build());
        PolicyRule rule = PolicyRule.builder().policy(policy).build();
        rule.setConditions(new HashSet<>(Set.of(
                PolicyCondition.builder().rule(rule).expression("hasRole('ANALYST')").build())));
        policy.getRules().add(rule);
        when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of(policy));
        CustomDynamicAuthorizationManager manager = new CustomDynamicAuthorizationManager(
                policyRetrievalPoint, resolver, mock(ObjectMapper.class), contextHandler,
                mock(AuthorizationMetrics.class), mock(CentralAuditFacade.class), new PolicyCombiningEvaluator());
        manager.setCombiningAlgorithm(CombiningAlgorithm.DENY_OVERRIDES);
        manager.setNoMatchingUrlPolicyDecision(NoPolicyDecision.DENY);
        manager.setDelegatorAuthority(delegatorAuthority, () -> enforced);
        manager.reload();
        return manager;
    }

    private static MockHttpServletRequest request(DelegationStamp stamp) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", REQUEST_PATH);
        request.setAttribute(BridgeRequestAttributes.DELEGATION_STAMP, stamp);
        return request;
    }

    private static DelegationStamp stamp(String subject, boolean delegated) {
        return new DelegationStamp(subject, "report-bot", delegated, null, null, null, List.of(), List.of(),
                null, null, null, null, Map.of());
    }
}
