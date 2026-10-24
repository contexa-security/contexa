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
import io.contexa.contexacommon.enums.ZeroTrustAction;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A1-9 (AG-11d): URL policies can state who the request acts as (an agent for a person, an agent on its own, a
 * person), which agent, for whom, through how many delegations and within which delegated scope; a policy without
 * these conditions decides as before.
 */
class CustomDynamicAuthorizationManagerAgentConditionTest {

    private static final String REQUEST_PATH = "/api/reports/export";

    private final PolicyRetrievalPoint policyRetrievalPoint = mock(PolicyRetrievalPoint.class);
    private final ContextHandler contextHandler = mock(ContextHandler.class);
    private final ZeroTrustActionRepository actions = mock(ZeroTrustActionRepository.class);
    private final Authentication caller = UsernamePasswordAuthenticationToken.authenticated(
            "alice", "n/a", AuthorityUtils.createAuthorityList("ROLE_USER"));
    private ExpressionAuthorizationManagerResolver resolver;

    @BeforeEach
    void setUp() {
        when(contextHandler.create(any(Authentication.class), any(HttpServletRequest.class)))
                .thenAnswer(inv -> new AuthorizationContext(inv.getArgument(0), null,
                        new ResourceDetails("URL", REQUEST_PATH), "GET",
                        new EnvironmentDetails("127.0.0.1", LocalDateTime.now(), inv.getArgument(1)),
                        new HashMap<>()));
        CustomWebSecurityExpressionHandler handler = new CustomWebSecurityExpressionHandler(
                contextHandler, mock(AuditLogRepository.class), actions,
                new NullRoleHierarchy());
        resolver = new ExpressionAuthorizationManagerResolver(List.of(
                new AuthenticatedExpressionEvaluator(),
                new AuthorityExpressionEvaluator(),
                new WebSpelExpressionEvaluator()), handler);
    }

    @Test
    void aMaximumDelegationChainDepthRefusesLongerChains() {
        CustomDynamicAuthorizationManager manager = manager(
                "!isAgent() or delegationChainDepthAtMost(1)");

        assertThat(granted(manager, delegated("report-bot", 1, List.of(), List.of()))).isTrue();
        assertThat(granted(manager, delegated("report-bot", 2, List.of(), List.of()))).isFalse();
        assertThat(granted(manager, null)).isTrue();
    }

    @Test
    void anAgentIsKeptWithinTheDelegatedScope() {
        CustomDynamicAuthorizationManager manager = manager(
                "!isDelegatedAgent() or (delegationAllowsOperation('export') and delegationAllowsResource('/api/reports/export'))");

        assertThat(granted(manager, delegated("report-bot", 1, List.of("read", "EXPORT"), List.of("/api/reports/*"))))
                .isTrue();
        assertThat(granted(manager, delegated("report-bot", 1, List.of("read"), List.of("/api/reports/*")))).isFalse();
        assertThat(granted(manager, delegated("report-bot", 1, List.of("export"), List.of("/api/orders/*")))).isFalse();
    }

    @Test
    void anAgentIsNamedAndToldFromAPersonOrAnAgentOnItsOwn() {
        CustomDynamicAuthorizationManager onlyReportBotForAlice = manager(
                "isDelegatedAgent() and isAgentIn('report-bot') and getDelegatorId() == 'alice'");
        CustomDynamicAuthorizationManager noAutonomousAgents = manager("!isAutonomousAgent()");

        assertThat(granted(onlyReportBotForAlice, delegated("report-bot", 1, List.of(), List.of()))).isTrue();
        assertThat(granted(onlyReportBotForAlice, delegated("other-bot", 1, List.of(), List.of()))).isFalse();
        assertThat(granted(noAutonomousAgents, autonomous("report-bot"))).isFalse();
        assertThat(granted(noAutonomousAgents, null)).isTrue();
    }

    @Test
    void aDelegationThatRequiresApprovalCanBeRefusedByPolicy() {
        CustomDynamicAuthorizationManager manager = manager("!delegationRequiresApproval()");
        DelegationStamp needsApproval = new DelegationStamp("alice", "report-bot", true, null, null, null,
                List.of(), List.of(), true, null, null, null, Map.of());

        assertThat(granted(manager, needsApproval)).isFalse();
        assertThat(granted(manager, delegated("report-bot", 1, List.of(), List.of()))).isTrue();
    }

    /** docs/agent A5-2: the person's confirmation of the very request is a fact a policy can let it through on. */
    @Test
    void aDelegationThatRequiresApprovalIsLetThroughOnceThePersonConfirmedTheRequest() {
        CustomDynamicAuthorizationManager manager = manager("!delegationRequiresApproval() or agentRequestConfirmed()");
        DelegationStamp needsApproval = new DelegationStamp("alice", "report-bot", true, null, null, null,
                List.of(), List.of(), true, null, null, null, Map.of());

        assertThat(granted(manager, needsApproval)).isFalse();
        assertThat(granted(manager, needsApproval, "confirmation-1")).isTrue();
    }

    /** docs/agent A5-2: a confirmed request answers the agent's CHALLENGE for that request; a BLOCK stays. */
    @Test
    void aConfirmedAgentRequestReadsTheChallengeAsAllowed() {
        CustomDynamicAuthorizationManager manager = manager("isAllowed()");
        when(actions.getCurrentAction("alice")).thenReturn(ZeroTrustAction.ALLOW);
        when(actions.getCurrentAction("alice::agent::report-bot"))
                .thenReturn(ZeroTrustAction.CHALLENGE, ZeroTrustAction.CHALLENGE, ZeroTrustAction.BLOCK);
        DelegationStamp agent = delegated("report-bot", 1, List.of(), List.of());

        assertThat(granted(manager, agent)).isFalse();
        assertThat(granted(manager, agent, "confirmation-1")).isTrue();
        assertThat(granted(manager, agent, "confirmation-1")).isFalse();
    }

    /** docs/agent A5-7 (A1-9): a policy can cap an agent's calls per minute, as the call limits counted them. */
    @Test
    void aPolicyCapsAnAgentsCallsPerMinute() {
        CustomDynamicAuthorizationManager manager = manager("agentCallsInLastMinuteAtMost(30)");
        DelegationStamp agent = delegated("report-bot", 1, List.of(), List.of());

        assertThat(grantedWithCalls(manager, agent, 30)).isTrue();
        assertThat(grantedWithCalls(manager, agent, 31)).isFalse();
        assertThat(grantedWithCalls(manager, null, 500)).isTrue();
    }

    private boolean grantedWithCalls(CustomDynamicAuthorizationManager manager, DelegationStamp stamp, int calls) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", REQUEST_PATH);
        if (stamp != null) {
            request.setAttribute(BridgeRequestAttributes.DELEGATION_STAMP, stamp);
        }
        request.setAttribute(BridgeRequestAttributes.AGENT_RECENT_CALLS, calls);
        return manager.check(() -> caller, new RequestAuthorizationContext(request)).isGranted();
    }

    @Test
    void aPolicyWithoutAgentConditionsDecidesAsBefore() {
        CustomDynamicAuthorizationManager manager = manager("hasRole('USER')");

        assertThat(granted(manager, null)).isTrue();
        assertThat(granted(manager, delegated("report-bot", 3, List.of(), List.of()))).isTrue();
    }

    private boolean granted(CustomDynamicAuthorizationManager manager, DelegationStamp stamp) {
        return granted(manager, stamp, null);
    }

    private boolean granted(CustomDynamicAuthorizationManager manager, DelegationStamp stamp, String confirmation) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", REQUEST_PATH);
        if (stamp != null) {
            request.setAttribute(BridgeRequestAttributes.DELEGATION_STAMP, stamp);
        }
        if (confirmation != null) {
            request.setAttribute(BridgeRequestAttributes.AGENT_CONFIRMATION, confirmation);
        }
        return manager.check(() -> caller, new RequestAuthorizationContext(request)).isGranted();
    }

    private static DelegationStamp delegated(String agentId, int depth, List<String> operations, List<String> resources) {
        return new DelegationStamp("alice", agentId, true, null, null, null, new ArrayList<>(operations),
                new ArrayList<>(resources), null, null, null, null, Map.of("delegationChainDepth", depth));
    }

    private static DelegationStamp autonomous(String agentId) {
        return new DelegationStamp(agentId, agentId, false, null, null, null, List.of(), List.of(),
                null, null, null, null, Map.of());
    }

    private CustomDynamicAuthorizationManager manager(String condition) {
        Policy policy = Policy.builder().id(1L).name("reports").effect(Policy.Effect.ALLOW).priority(1)
                .isActive(true).approvalStatus(Policy.ApprovalStatus.APPROVED).build();
        policy.getTargets().add(PolicyTarget.builder()
                .policy(policy).targetType("URL").targetIdentifier("/api/reports/**").httpMethod("ANY").build());
        PolicyRule rule = PolicyRule.builder().policy(policy).build();
        rule.setConditions(new HashSet<>(Set.of(PolicyCondition.builder().rule(rule).expression(condition).build())));
        policy.getRules().add(rule);
        when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of(policy));
        CustomDynamicAuthorizationManager manager = new CustomDynamicAuthorizationManager(
                policyRetrievalPoint, resolver, mock(ObjectMapper.class), contextHandler,
                mock(AuthorizationMetrics.class), mock(CentralAuditFacade.class), new PolicyCombiningEvaluator());
        manager.setCombiningAlgorithm(CombiningAlgorithm.DENY_OVERRIDES);
        manager.setNoMatchingUrlPolicyDecision(NoPolicyDecision.DENY);
        manager.reload();
        return manager;
    }
}
