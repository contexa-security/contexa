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
import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.metrics.AuthorizationMetrics;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
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
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.Supplier;

@Slf4j
@RequiredArgsConstructor
public class CustomDynamicAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

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
                .sorted(Comparator.comparingInt(Policy::getPriority))
                .toList();

        for (Policy policy : urlPolicies) {
            if (!isExecutable(policy)) {
                continue;
            }
            String expression = getExpressionFromPolicy(policy);
            for (PolicyTarget target : policy.getTargets()) {
                if (!"URL".equals(target.getTargetType())) {
                    continue;
                }
                String httpMethod = target.getHttpMethod();
                RequestMatcher matcher;
                if (httpMethod != null && !"ANY".equals(httpMethod) && !"ALL".equals(httpMethod)) {
                    matcher = PathPatternRequestMatcher.withDefaults()
                            .matcher(HttpMethod.valueOf(httpMethod), target.getTargetIdentifier());
                } else {
                    matcher = PathPatternRequestMatcher.withDefaults().matcher(target.getTargetIdentifier());
                }
                loadedMappings.add(new RequestMatcherEntry<>(matcher, managerResolver.resolve(expression)));
            }
        }
        mappings = List.copyOf(loadedMappings);
    }

    private boolean isExecutable(Policy policy) {
        if (policy == null || !Boolean.TRUE.equals(policy.getIsActive())) {
            return false;
        }
        Policy.ApprovalStatus status = policy.getApprovalStatus();
        return status == Policy.ApprovalStatus.APPROVED || status == Policy.ApprovalStatus.NOT_REQUIRED;
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
        List<AuthorizationDecision> matchedDecisions = new ArrayList<>();
        List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> currentMappings = mappings;

        for (RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> mapping : currentMappings) {
            RequestMatcher.MatchResult matchResult = mapping.getRequestMatcher().matcher(request);
            if (!matchResult.isMatch()) {
                continue;
            }
            AuthorizationDecision decision = mapping.getEntry().check(authenticationSupplier,
                    new RequestAuthorizationContext(request, matchResult.getVariables()));
            if (decision == null) {
                continue;
            }
            if (firstApplicable) {
                return complete(authentication, request, decision, startedAt);
            }
            matchedDecisions.add(decision);
        }

        AuthorizationDecision finalDecision = matchedDecisions.isEmpty()
                ? new AuthorizationDecision(currentNoPolicyDecision.isGranted())
                : combiningEvaluator.evaluate(matchedDecisions, currentAlgorithm);
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
        String principal = authentication != null && authentication.getPrincipal() instanceof UserDto userDto
                ? userDto.getName() : "anonymousUser";
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
}
