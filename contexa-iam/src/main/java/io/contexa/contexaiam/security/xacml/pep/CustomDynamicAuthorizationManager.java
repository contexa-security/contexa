package io.contexa.contexaiam.security.xacml.pep;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.metrics.AuthorizationMetrics;
import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import io.contexa.contexacommon.domain.TrustAssessment;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
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
    private static final Pattern HAS_PERMISSION_PATTERN = Pattern.compile("\\s*(?:and\\s+)?hasPermission\\([^)]*\\)(?:\\s*and)?\\s*");
    private final ObjectMapper objectMapper;
    private final ContextHandler contextHandler;
    private final ZeroTrustEventPublisher zeroTrustEventPublisher;
    private final AuthorizationMetrics metricsCollector;
    private final CentralAuditFacade centralAuditFacade;

    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        initialize();
    }

    private void initialize() {
        this.mappings = new ArrayList<>();

        List<Policy> urlPolicies = policyRetrievalPoint.findUrlPolicies();

        for (Policy policy : urlPolicies) {
            if (policy.isAIGenerated() && (policy.getApprovalStatus() != Policy.ApprovalStatus.APPROVED || !policy.getIsActive())) {
                continue;
            }

            String expression = getExpressionFromPolicy(policy);

            for (PolicyTarget target : policy.getTargets()) {
                if ("URL".equals(target.getTargetType())) {
                    String httpMethod = target.getHttpMethod();
                    RequestMatcher matcher;
                    if (httpMethod != null && !"ANY".equals(httpMethod) && !"ALL".equals(httpMethod)) {
                        matcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.valueOf(httpMethod), target.getTargetIdentifier());
                    } else {
                        matcher = PathPatternRequestMatcher.withDefaults().matcher(target.getTargetIdentifier());
                    }
                    AuthorizationManager<RequestAuthorizationContext> manager = managerResolver.resolve(expression);
                    this.mappings.add(new RequestMatcherEntry<>(matcher, manager));
                }
            }
        }
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authenticationSupplier, RequestAuthorizationContext context) {

        final HttpServletRequest request = context.getRequest();
        final Authentication authentication = authenticationSupplier.get();

        AuthorizationContext authorizationContext = contextHandler.create(authentication, request);
        AuthorizationDecision authorizationDecision = new AuthorizationDecision(true);
        for (RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> mapping : this.mappings) {
            RequestMatcher.MatchResult matchResult = mapping.getRequestMatcher().matcher(context.getRequest());
            if (matchResult.isMatch()) {
                AuthorizationManager<RequestAuthorizationContext> manager = mapping.getEntry();
                RequestAuthorizationContext enrichedContext =
                        new RequestAuthorizationContext(context.getRequest(), matchResult.getVariables());
                authorizationDecision = manager.check(authenticationSupplier, enrichedContext);

                if (!authorizationDecision.isGranted()) {
                    logAuthorizationAttempt(authentication, authorizationContext, authorizationDecision, request);
                }
                return authorizationDecision;
            }
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
            finalExpression = "!(" + finalExpression + ")";
        }
        return stripHasPermissionForUrl(finalExpression);
    }

    private String stripHasPermissionForUrl(String expression) {
        String cleaned = HAS_PERMISSION_PATTERN.matcher(expression).replaceAll(" ");
        cleaned = cleaned.replaceAll("\\s+and\\s+and\\s+", " and ");
        cleaned = cleaned.replaceAll("^\\s*and\\s+", "");
        cleaned = cleaned.replaceAll("\\s+and\\s*$", "");
        cleaned = cleaned.trim();
        return cleaned.isEmpty() ? "denyAll" : cleaned;
    }

    private void logAuthorizationAttempt(Authentication authentication, AuthorizationContext context,
                                         AuthorizationDecision decision, HttpServletRequest request) {
        String principal = (authentication != null && authentication.getPrincipal() instanceof UserDto userDto)
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

        if (centralAuditFacade != null) {
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
    }

    public synchronized void reload() {
        policyRetrievalPoint.clearUrlPoliciesCache();
        initialize();
    }
}