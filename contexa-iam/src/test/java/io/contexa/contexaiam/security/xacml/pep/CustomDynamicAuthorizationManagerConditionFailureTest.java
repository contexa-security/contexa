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
import io.contexa.contexacore.autonomous.audit.AuditRecord;
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
import io.contexa.contexaiam.security.xacml.prp.PolicyGeneration;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * D68: a URL policy whose condition cannot be evaluated on a request denied nothing and permitted nothing: the request
 * failed with 500, and with it every request the policy covers. Such a condition denies the request now, a function no
 * context has is refused when the policy is loaded, and the seed template's {@code #isBusinessHours()} evaluates.
 */
class CustomDynamicAuthorizationManagerConditionFailureTest {

    private static final String PATH = "/api/orders/**";
    private static final String REQUEST_PATH = "/api/orders/42";

    private final PolicyRetrievalPoint policyRetrievalPoint = mock(PolicyRetrievalPoint.class);
    private final ContextHandler contextHandler = mock(ContextHandler.class);
    private ExpressionAuthorizationManagerResolver resolver;

    private final Authentication user = UsernamePasswordAuthenticationToken.authenticated(
            "alice", "n/a", AuthorityUtils.createAuthorityList("ROLE_USER"));

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
    @DisplayName("a condition that fails on the request denies it instead of failing it, for either effect")
    void aConditionThatFailsDeniesTheRequest() {
        for (Policy.Effect effect : Policy.Effect.values()) {
            CustomDynamicAuthorizationManager manager = manager(
                    policy(1L, effect, 10, "principal.nickname == 'alice'"),
                    policy(2L, Policy.Effect.ALLOW, 20, "permitAll"));

            AuthorizationDecision decision = check(manager);

            assertThat(decision.isGranted()).as(effect.name()).isFalse();
        }
    }

    @Test
    @DisplayName("a function no context has is refused when the policy loads, and its targets are denied")
    void anUnknownFunctionIsRefusedAtLoad() {
        CustomDynamicAuthorizationManager manager = manager(policy(1L, Policy.Effect.ALLOW, 10, "#isBusinesHours()"));

        assertThat(check(manager).isGranted()).isFalse();
    }

    @Test
    @DisplayName("the seed template's #isBusinessHours() is a function the policies can call")
    void theBusinessHoursFunctionEvaluates() {
        CustomDynamicAuthorizationManager manager = manager(
                policy(1L, Policy.Effect.ALLOW, 10, "#isBusinessHours() or isAuthenticated()"));

        assertThat(check(manager).isGranted()).isTrue();
    }

    @Test
    @DisplayName("a failure that is no evaluation of a condition is not turned into a decision")
    void anyOtherFailurePropagates() {
        IllegalStateException challenge = new IllegalStateException("challenge raised on purpose");
        CustomDynamicAuthorizationManager.FailClosedAuthorizationManager guarded =
                new CustomDynamicAuthorizationManager.FailClosedAuthorizationManager(
                        (authentication, context) -> {
                            throw challenge;
                        }, 1L, "policy-1");

        assertThatThrownBy(() -> guarded.check(() -> user,
                new RequestAuthorizationContext(new MockHttpServletRequest("GET", REQUEST_PATH))))
                .isSameAs(challenge);
    }

    @Test
    @DisplayName("D29: a decision without an AI assessment is audited with a code, not an English sentence")
    void theAuditReasonIsACode() {
        CentralAuditFacade audit = mock(CentralAuditFacade.class);
        when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of(policy(1L, Policy.Effect.ALLOW, 10, "permitAll")));
        CustomDynamicAuthorizationManager manager = new CustomDynamicAuthorizationManager(
                policyRetrievalPoint, resolver, mock(ObjectMapper.class), contextHandler,
                mock(AuthorizationMetrics.class), audit, new PolicyCombiningEvaluator());
        manager.reload();

        check(manager);

        ArgumentCaptor<AuditRecord> recorded = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(recorded.capture());
        assertThat(recorded.getValue().getReason()).isEqualTo(AuthorizationAuditReason.STATIC_RULE);
    }

    @Test
    @DisplayName("each reload moves the policy generation on, so what is kept from the policies is worked out again")
    void eachReloadMovesTheGenerationOn() {
        CustomDynamicAuthorizationManager manager = manager(policy(1L, Policy.Effect.ALLOW, 10, "permitAll"));
        long before = PolicyGeneration.current();

        manager.reload();

        assertThat(PolicyGeneration.current()).isGreaterThan(before);
    }

    private AuthorizationDecision check(CustomDynamicAuthorizationManager manager) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", REQUEST_PATH);
        return manager.check(() -> user, new RequestAuthorizationContext(request));
    }

    private Policy policy(long id, Policy.Effect effect, int priority, String condition) {
        Policy policy = Policy.builder().id(id).name("policy-" + id).effect(effect).priority(priority)
                .isActive(true).approvalStatus(Policy.ApprovalStatus.APPROVED).build();
        policy.getTargets().add(PolicyTarget.builder()
                .policy(policy).targetType("URL").targetIdentifier(PATH).httpMethod("ANY").build());
        PolicyRule rule = PolicyRule.builder().policy(policy).build();
        rule.setConditions(Set.of(PolicyCondition.builder().rule(rule).expression(condition).build()));
        policy.getRules().add(rule);
        return policy;
    }

    private CustomDynamicAuthorizationManager manager(Policy... policies) {
        when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of(policies));
        CustomDynamicAuthorizationManager manager = new CustomDynamicAuthorizationManager(
                policyRetrievalPoint, resolver, mock(ObjectMapper.class), contextHandler,
                mock(AuthorizationMetrics.class), mock(CentralAuditFacade.class), new PolicyCombiningEvaluator());
        manager.setCombiningAlgorithm(CombiningAlgorithm.FIRST_APPLICABLE);
        manager.setNoMatchingUrlPolicyDecision(NoPolicyDecision.PERMIT);
        manager.reload();
        return manager;
    }
}
