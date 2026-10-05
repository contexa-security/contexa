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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.TrustAssessment;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.metrics.AuthorizationMetrics;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyEvaluationOrder;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.PolicyExpressionValidator;
import io.contexa.contexaiam.security.xacml.pdp.translator.PolicyExpressionConverter;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * URL policy enforcement point.
 *
 * <p>ALLOW policies yield Permit when their condition holds and Deny otherwise. DENY policies yield
 * Deny when their condition holds and NotApplicable otherwise, so a non-matching DENY policy never
 * grants access and never hides lower-priority policies. NotApplicable results are excluded from
 * combining; when matching policies exist but none applies, DENY_UNLESS_PERMIT denies and the other
 * algorithms use the no-matching-policy decision.</p>
 *
 * <p>A policy whose condition is rejected by {@link PolicyExpressionValidator} while loading is not
 * compiled. Its URL targets are mapped to a constant Deny instead, because dropping the policy could
 * open the target through the no-matching-policy default.</p>
 */
@Slf4j
@RequiredArgsConstructor
public class CustomDynamicAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private static final AuthorizationManager<RequestAuthorizationContext> REJECTED_POLICY_MANAGER =
            (authentication, context) -> new AuthorizationDecision(false);

    private final PolicyRetrievalPoint policyRetrievalPoint;
    private final ExpressionAuthorizationManagerResolver managerResolver;
    private final ObjectMapper objectMapper;
    private final ContextHandler contextHandler;
    private final AuthorizationMetrics metricsCollector;
    private final CentralAuditFacade centralAuditFacade;
    private final PolicyCombiningEvaluator combiningEvaluator;
    private final PolicyExpressionConverter expressionConverter = new PolicyExpressionConverter();

    private volatile List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings = List.of();
    @Setter
    private volatile CombiningAlgorithm combiningAlgorithm;
    private volatile NoPolicyDecision noMatchingUrlPolicyDecision = NoPolicyDecision.PERMIT;

    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        initialize();
    }

    private void initialize() {
        List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> loadedMappings = new ArrayList<>();
        List<Policy> urlPolicies = policyRetrievalPoint.findUrlPolicies().stream()
                .sorted(PolicyEvaluationOrder.urlOrder())
                .toList();

        for (Policy policy : urlPolicies) {
            if (!PolicyEvaluationOrder.isExecutable(policy)) {
                continue;
            }
            List<PolicyTarget> urlTargets = policy.getTargets().stream()
                    .filter(target -> "URL".equals(target.getTargetType()))
                    .toList();
            if (urlTargets.isEmpty()) {
                continue;
            }
            AuthorizationManager<RequestAuthorizationContext> policyManager = createPolicyManager(policy);
            for (PolicyTarget target : urlTargets) {
                RequestMatcher matcher = UrlPolicyTargetMatcher.requestMatcher(target);
                loadedMappings.add(new RequestMatcherEntry<>(matcher, policyManager));
            }
        }
        mappings = List.copyOf(loadedMappings);
    }

    private AuthorizationManager<RequestAuthorizationContext> createPolicyManager(Policy policy) {
        String violation;
        try {
            String expression = getExpressionFromPolicy(policy);
            violation = expressionConverter.findLoadViolation(policy, expression);
            if (violation == null) {
                AuthorizationManager<RequestAuthorizationContext> conditionManager = managerResolver.resolve(expression);
                return policy.getEffect() == Policy.Effect.DENY
                        ? new DenyEffectAuthorizationManager(conditionManager)
                        : conditionManager;
            }
        } catch (RuntimeException e) {
            violation = "Policy expression cannot be compiled: " + e.getMessage();
        }
        log.error("URL policy rejected while loading, its targets are denied. policyId={}, name={}, reason={}",
                policy.getId(), policy.getName(), violation);
        return REJECTED_POLICY_MANAGER;
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authenticationSupplier,
                                       RequestAuthorizationContext context) {
        long startedAt = System.nanoTime();
        HttpServletRequest request = context.getRequest();
        Authentication authentication = authenticationSupplier.get();
        CombiningAlgorithm currentAlgorithm = combiningAlgorithm;
        NoPolicyDecision currentNoPolicyDecision = noMatchingUrlPolicyDecision;
        boolean firstApplicable = currentAlgorithm == CombiningAlgorithm.FIRST_APPLICABLE;
        // One entry per matching policy; null marks a NotApplicable DENY policy.
        List<AuthorizationDecision> matchedDecisions = new ArrayList<>();
        List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> currentMappings = mappings;

        for (RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> mapping : currentMappings) {
            RequestMatcher.MatchResult matchResult = mapping.getRequestMatcher().matcher(request);
            if (!matchResult.isMatch()) {
                continue;
            }
            AuthorizationDecision decision = mapping.getEntry().check(authenticationSupplier,
                    new RequestAuthorizationContext(request, matchResult.getVariables()));
            if (decision != null && firstApplicable) {
                return complete(authentication, request, decision, startedAt);
            }
            matchedDecisions.add(decision);
        }

        AuthorizationDecision finalDecision = combiningEvaluator.evaluate(
                matchedDecisions, currentAlgorithm, currentNoPolicyDecision);
        return complete(authentication, request, finalDecision, startedAt);
    }

    private AuthorizationDecision complete(Authentication authentication, HttpServletRequest request,
                                           AuthorizationDecision decision, long startedAt) {
        logAuthorizationAttempt(authentication, createAuthorizationContext(authentication, request), decision, request);
        if (metricsCollector != null) {
            metricsCollector.recordUrlAuth(System.nanoTime() - startedAt);
            metricsCollector.recordAuthzDecision();
        }
        return decision;
    }

    private AuthorizationContext createAuthorizationContext(Authentication authentication, HttpServletRequest request) {
        return contextHandler.create(authentication, request);
    }

    public String getExpressionFromPolicy(Policy policy) {
        return expressionConverter.toExpression(policy);
    }

    private void logAuthorizationAttempt(Authentication authentication, AuthorizationContext context,
                                         AuthorizationDecision decision, HttpServletRequest request) {
        String principal = authentication != null ? authentication.getName() : "anonymousUser";
        String resource = context.resource().identifier();
        String action = context.action();
        String result = decision.isGranted() ? "ALLOW" : "DENY";
        String clientIp = context.environment().remoteIp();

        String reason;
        Double riskScore = null;
        TrustAssessment assessment = (TrustAssessment) context.attributes().get("ai_assessment");
        if (assessment != null) {
            try {
                reason = "AI assessment result: " + objectMapper.writeValueAsString(assessment);
            } catch (JsonProcessingException e) {
                reason = "AI assessment result serialization failed. Score: " + assessment.score();
            }
            riskScore = 1.0 - assessment.score();
        } else {
            reason = "Static rule matching";
        }

        if (centralAuditFacade == null) {
            return;
        }
        try {
            AuditEventCategory category = decision.isGranted()
                    ? AuditEventCategory.AUTHORIZATION_GRANTED
                    : AuditEventCategory.AUTHORIZATION_DENIED;
            centralAuditFacade.recordAsync(AuditRecord.builder()
                    .eventCategory(category)
                    .principalName(principal)
                    .eventSource("IAM")
                    .clientIp(clientIp)
                    .sessionId(request.getSession(false) != null ? request.getSession(false).getId() : null)
                    .userAgent(request.getHeader("User-Agent"))
                    .resourceIdentifier(resource)
                    .resourceUri(request.getRequestURI())
                    .requestUri(request.getRequestURI())
                    .httpMethod(request.getMethod())
                    .action(action)
                    .decision(result)
                    .reason(reason)
                    .outcome(decision.isGranted() ? "GRANTED" : "DENIED")
                    .riskScore(riskScore)
                    .build());
        } catch (Exception e) {
            log.error("Failed to audit authorization attempt", e);
        }
    }

    public synchronized void reload() {
        policyRetrievalPoint.clearUrlPoliciesCache();
        policyRetrievalPoint.clearMethodPoliciesCache();
        initialize();
    }

    public void setNoMatchingUrlPolicyDecision(NoPolicyDecision noMatchingUrlPolicyDecision) {
        this.noMatchingUrlPolicyDecision = noMatchingUrlPolicyDecision != null
                ? noMatchingUrlPolicyDecision
                : NoPolicyDecision.PERMIT;
    }

    public CombiningAlgorithm getCombiningAlgorithm() {
        return combiningAlgorithm;
    }

    public NoPolicyDecision getNoMatchingUrlPolicyDecision() {
        return noMatchingUrlPolicyDecision;
    }

    /**
     * Applies the DENY effect to a condition: a satisfied condition is Deny and an unsatisfied
     * condition is NotApplicable ({@code null}).
     */
    private record DenyEffectAuthorizationManager(AuthorizationManager<RequestAuthorizationContext> condition)
            implements AuthorizationManager<RequestAuthorizationContext> {

        @Override
        public AuthorizationDecision check(Supplier<Authentication> authentication,
                                           RequestAuthorizationContext context) {
            AuthorizationDecision conditionResult = condition.check(authentication, context);
            return PolicyCombiningEvaluator.applyEffect(
                    Policy.Effect.DENY, conditionResult != null && conditionResult.isGranted());
        }
    }
}
