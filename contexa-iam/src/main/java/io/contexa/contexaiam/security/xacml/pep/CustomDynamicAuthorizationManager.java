package io.contexa.contexaiam.security.xacml.pep;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust.EventPublishingMetrics;
import io.contexa.contexaiam.admin.web.monitoring.service.AuditLogService;
import io.contexa.contexacommon.dto.UserDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import io.contexa.contexacommon.domain.TrustAssessment;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


@Slf4j
@RequiredArgsConstructor
public class CustomDynamicAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final PolicyRetrievalPoint policyRetrievalPoint;
    private final ExpressionAuthorizationManagerResolver managerResolver;
    private List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings;
    private static final Pattern AUTHORITY_PATTERN = Pattern.compile("^[A-Z_]+$");
    private final AuditLogService auditLogService;
    private final ObjectMapper objectMapper;
    private final ContextHandler contextHandler;
    private final ZeroTrustEventPublisher zeroTrustEventPublisher;
    private final EventPublishingMetrics metricsCollector;


    
    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        log.info("ApplicationContext refreshed. Initializing dynamic authorization mappings...");
        initialize();
    }

    
    private void initialize() {
        log.info("Loading dynamic authorization mappings from Policy model...");
        this.mappings = new ArrayList<>();

        List<Policy> urlPolicies = policyRetrievalPoint.findUrlPolicies();

        for (Policy policy : urlPolicies) {
            if (policy.isAIGenerated() &&
                (policy.getApprovalStatus() != Policy.ApprovalStatus.APPROVED || !policy.getIsActive())) {
                log.debug("Skipping AI policy '{}' - not approved or inactive", policy.getName());
                continue;
            }

            String expression = getExpressionFromPolicy(policy);

            for (PolicyTarget target : policy.getTargets()) {
                if ("URL".equals(target.getTargetType())) {
                    RequestMatcher matcher = PathPatternRequestMatcher.withDefaults().matcher(target.getTargetIdentifier());
                    AuthorizationManager<RequestAuthorizationContext> manager = managerResolver.resolve(expression);
                    this.mappings.add(new RequestMatcherEntry<>(matcher, manager));

                    String policySource = policy.isAIGenerated() ? " [AI-" + policy.getSource() + "]" : "";
                    log.debug("Policy mapping loaded - URL '{}' mapped to expression '{}' using {}{}",
                            target.getTargetIdentifier(), expression, manager.getClass().getSimpleName(), policySource);
                }
            }
        }
        log.info("Initialization complete. {} URL policy mappings configured.", this.mappings.size());
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authenticationSupplier, RequestAuthorizationContext context) {
        log.trace("Checking authorization for request: {}", context.getRequest().getRequestURI());

        final HttpServletRequest request = context.getRequest();
        final Authentication authentication = authenticationSupplier.get();

        AuthorizationContext authorizationContext = contextHandler.create(authentication, request);

        for (RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> mapping : this.mappings) {
            if (mapping.getRequestMatcher().matcher(context.getRequest()).isMatch()) {
                log.debug("Request matched by '{}'. Delegating to its AuthorizationManager.", mapping.getRequestMatcher());

                AuthorizationManager<RequestAuthorizationContext> manager = mapping.getEntry();

                return manager.check(authenticationSupplier, context);
            }
        }
        log.trace("No matching policy found for request. Allowing access by default.");
        AuthorizationDecision authorizationDecision = new AuthorizationDecision(true);
        logAuthorizationAttempt(authentication, authorizationContext, authorizationDecision);

        if (zeroTrustEventPublisher != null && !authorizationDecision.isGranted()) {
            long startTime = System.nanoTime();
            zeroTrustEventPublisher.publishWebAuthorization(authentication, request, authorizationDecision);

            long duration = System.nanoTime() - startTime;

            if (metricsCollector != null) {
                metricsCollector.recordUrlAuth(duration);
                metricsCollector.recordAuthzDecision();
            }

            log.debug("Authorization denied event published for: {}", request.getRequestURI());
        }

        return authorizationDecision;
    }

    
    public String getExpressionFromPolicy(Policy policy) {
        List<String> conditionExpressions = policy.getRules().stream()
                .flatMap(rule -> rule.getConditions().stream())
                .map(PolicyCondition::getExpression)
                .toList();

        if (conditionExpressions.isEmpty()) {
            return (policy.getEffect() == Policy.Effect.ALLOW) ? "permitAll" : "denyAll";
        }

        String finalExpression;

        
        if (conditionExpressions.size() == 1) {
            finalExpression = conditionExpressions.getFirst(); 

            
        } else {
            boolean allAreSimpleAuthorities = conditionExpressions.stream().allMatch(expr -> AUTHORITY_PATTERN.matcher(expr).matches());

            
            if (allAreSimpleAuthorities) {
                finalExpression = "hasAnyAuthority(" +
                        conditionExpressions.stream().map(auth -> "'" + auth + "'").collect(Collectors.joining(",")) +
                        ")";
                
            } else {
                finalExpression = conditionExpressions.stream()
                        .map(expr -> "(" + expr + ")")
                        .collect(Collectors.joining(" or "));
            }
        }

        if (policy.getEffect() == Policy.Effect.DENY) {
            return "!(" + finalExpression + ")";
        }
        return finalExpression;
    }

    
    private void logAuthorizationAttempt(Authentication authentication, AuthorizationContext context, AuthorizationDecision decision) {

        String principal = (authentication != null && authentication.getPrincipal() instanceof UserDto userDto) ? userDto.getName() : "anonymousUser";
        String resource = context.resource().identifier();
        String action = context.action();
        String result = decision.isGranted() ? "ALLOW" : "DENY";
        String clientIp = context.environment().remoteIp();

        String reason;
        TrustAssessment assessment = (TrustAssessment) context.attributes().get("ai_assessment");

        if (assessment != null) {
            try {
                reason = "AI 평가 결과: " + objectMapper.writeValueAsString(assessment);
            } catch (JsonProcessingException e) {
                reason = "AI 평가 결과 직렬화 실패. 점수: " + assessment.score();
            }
        } else {
            reason = "정적 규칙 매칭"; 
        }

        auditLogService.logDecision(principal, resource, action, result, reason, clientIp);
    }

    public synchronized void reload() {
        log.info("Reloading dynamic authorization mappings from data source...");
        policyRetrievalPoint.clearUrlPoliciesCache();
        initialize();
        log.info("Dynamic authorization mappings reloaded successfully.");
    }
}