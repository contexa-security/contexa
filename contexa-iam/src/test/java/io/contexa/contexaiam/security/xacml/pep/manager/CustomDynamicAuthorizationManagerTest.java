package io.contexa.contexaiam.security.xacml.pep.manager;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.metrics.AuthorizationMetrics;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.ExpressionAuthorizationManagerResolver;
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
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.time.LocalDateTime;
import java.util.*;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CustomDynamicAuthorizationManagerTest {

    @Mock
    private PolicyRetrievalPoint policyRetrievalPoint;

    @Mock
    private ExpressionAuthorizationManagerResolver managerResolver;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private ContextHandler contextHandler;

    @Mock
    private ZeroTrustEventPublisher zeroTrustEventPublisher;

    @Mock
    private AuthorizationMetrics metricsCollector;

    @Mock
    private CentralAuditFacade centralAuditFacade;

    @Mock
    private Authentication authentication;

    @Mock
    private HttpServletRequest request;

    private CustomDynamicAuthorizationManager authorizationManager;

    @BeforeEach
    void setUp() {
        authorizationManager = new CustomDynamicAuthorizationManager(
                policyRetrievalPoint, managerResolver, objectMapper,
                contextHandler, zeroTrustEventPublisher, metricsCollector);
        authorizationManager.setCentralAuditFacade(centralAuditFacade);
    }

    @Nested
    @DisplayName("Policy loading on ContextRefreshedEvent")
    class PolicyLoadingTests {

        @Test
        @DisplayName("Should load URL policies on context refreshed event")
        void shouldLoadPoliciesOnContextRefresh() {
            when(policyRetrievalPoint.findUrlPolicies()).thenReturn(Collections.emptyList());

            authorizationManager.onApplicationEvent(mock(ContextRefreshedEvent.class));

            verify(policyRetrievalPoint).findUrlPolicies();
        }

        @Test
        @DisplayName("Should skip AI-generated policies that are not approved")
        void shouldSkipUnapprovedAiPolicies() {
            Policy aiPolicy = Policy.builder()
                    .name("ai-policy")
                    .effect(Policy.Effect.ALLOW)
                    .source(Policy.PolicySource.AI_GENERATED)
                    .approvalStatus(Policy.ApprovalStatus.PENDING)
                    .isActive(true)
                    .build();
            aiPolicy.setTargets(Set.of(PolicyTarget.builder()
                    .targetType("URL").targetIdentifier("/api/test").httpMethod("GET").build()));
            aiPolicy.setRules(new HashSet<>());

            when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of(aiPolicy));

            authorizationManager.onApplicationEvent(mock(ContextRefreshedEvent.class));

            verify(managerResolver, never()).resolve(any());
        }

        @Test
        @DisplayName("Should register approved AI-generated policies")
        void shouldRegisterApprovedAiPolicies() {
            Policy approvedPolicy = buildPolicyWithTarget("approved-policy",
                    Policy.Effect.ALLOW, Policy.PolicySource.AI_GENERATED,
                    Policy.ApprovalStatus.APPROVED, "/api/approved", "GET");
            approvedPolicy.setIsActive(true);

            PolicyRule rule = PolicyRule.builder().build();
            PolicyCondition condition = PolicyCondition.builder().expression("hasAuthority('ADMIN')").build();
            rule.setConditions(Set.of(condition));
            approvedPolicy.setRules(Set.of(rule));

            AuthorizationManager<RequestAuthorizationContext> resolvedManager = mock(AuthorizationManager.class);
            when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of(approvedPolicy));
            when(managerResolver.resolve(any())).thenReturn(resolvedManager);

            authorizationManager.onApplicationEvent(mock(ContextRefreshedEvent.class));

            verify(managerResolver).resolve("hasAuthority('ADMIN')");
        }
    }

    @Nested
    @DisplayName("SpEL extraction from conditions")
    class SpelExtractionTests {

        @Test
        @DisplayName("Should return permitAll for ALLOW policy without conditions")
        void shouldReturnPermitAllForAllowWithoutConditions() {
            Policy policy = Policy.builder().effect(Policy.Effect.ALLOW).build();
            policy.setRules(new HashSet<>());

            String expression = authorizationManager.getExpressionFromPolicy(policy);

            assertThat(expression).isEqualTo("permitAll");
        }

        @Test
        @DisplayName("Should return denyAll for DENY policy without conditions")
        void shouldReturnDenyAllForDenyWithoutConditions() {
            Policy policy = Policy.builder().effect(Policy.Effect.DENY).build();
            policy.setRules(new HashSet<>());

            String expression = authorizationManager.getExpressionFromPolicy(policy);

            assertThat(expression).isEqualTo("denyAll");
        }

        @Test
        @DisplayName("Should extract single condition expression")
        void shouldExtractSingleCondition() {
            Policy policy = Policy.builder().effect(Policy.Effect.ALLOW).build();
            PolicyRule rule = PolicyRule.builder().build();
            PolicyCondition condition = PolicyCondition.builder()
                    .expression("hasAuthority('ROLE_USER')").build();
            rule.setConditions(Set.of(condition));
            policy.setRules(Set.of(rule));

            String expression = authorizationManager.getExpressionFromPolicy(policy);

            assertThat(expression).isEqualTo("hasAuthority('ROLE_USER')");
        }

        @Test
        @DisplayName("Should negate expression for DENY effect")
        void shouldNegateForDenyEffect() {
            Policy policy = Policy.builder().effect(Policy.Effect.DENY).build();
            PolicyRule rule = PolicyRule.builder().build();
            PolicyCondition condition = PolicyCondition.builder()
                    .expression("hasAuthority('ROLE_BLOCKED')").build();
            rule.setConditions(Set.of(condition));
            policy.setRules(Set.of(rule));

            String expression = authorizationManager.getExpressionFromPolicy(policy);

            assertThat(expression).startsWith("!(");
            assertThat(expression).contains("hasAuthority('ROLE_BLOCKED')");
        }

        @Test
        @DisplayName("Should combine simple authorities with hasAnyAuthority")
        void shouldCombineSimpleAuthorities() {
            Policy policy = Policy.builder().effect(Policy.Effect.ALLOW).build();
            PolicyRule rule1 = PolicyRule.builder().build();
            PolicyCondition cond1 = PolicyCondition.builder().expression("ADMIN").build();
            rule1.setConditions(Set.of(cond1));

            PolicyRule rule2 = PolicyRule.builder().build();
            PolicyCondition cond2 = PolicyCondition.builder().expression("MANAGER").build();
            rule2.setConditions(Set.of(cond2));

            policy.setRules(Set.of(rule1, rule2));

            String expression = authorizationManager.getExpressionFromPolicy(policy);

            assertThat(expression).startsWith("hasAnyAuthority(");
            assertThat(expression).contains("'ADMIN'");
            assertThat(expression).contains("'MANAGER'");
        }
    }

    @Nested
    @DisplayName("check() method authorization decision")
    class CheckMethodTests {

        @Test
        @DisplayName("Should return granted=true when no mapping matches")
        void shouldReturnGrantedWhenNoMatch() {
            when(policyRetrievalPoint.findUrlPolicies()).thenReturn(Collections.emptyList());
            authorizationManager.onApplicationEvent(mock(ContextRefreshedEvent.class));

            when(request.getMethod()).thenReturn("GET");
            when(request.getRequestURI()).thenReturn("/api/unknown");
            when(request.getSession(false)).thenReturn(null);
            when(request.getHeader("User-Agent")).thenReturn("test");

            AuthorizationContext ctx = new AuthorizationContext(
                    authentication, null,
                    new ResourceDetails("URL", "/api/unknown"),
                    "GET",
                    new EnvironmentDetails("127.0.0.1", LocalDateTime.now(), request),
                    new HashMap<>());
            when(contextHandler.create(authentication, request)).thenReturn(ctx);

            RequestAuthorizationContext rac = new RequestAuthorizationContext(request);
            Supplier<Authentication> authSupplier = () -> authentication;

            AuthorizationDecision decision = authorizationManager.check(authSupplier, rac);

            assertThat(decision.isGranted()).isTrue();
        }
    }

    @Nested
    @DisplayName("reload() method")
    class ReloadTests {

        @Test
        @DisplayName("Should clear cache and reinitialize mappings")
        void shouldClearCacheAndReinitialize() {
            when(policyRetrievalPoint.findUrlPolicies()).thenReturn(Collections.emptyList());

            authorizationManager.reload();

            verify(policyRetrievalPoint).clearUrlPoliciesCache();
            verify(policyRetrievalPoint).findUrlPolicies();
        }
    }

    @Nested
    @DisplayName("Audit recording")
    class AuditTests {

        @Test
        @DisplayName("Should record audit when centralAuditFacade is present and no match found")
        void shouldRecordAuditOnNoMatch() {
            when(policyRetrievalPoint.findUrlPolicies()).thenReturn(Collections.emptyList());
            authorizationManager.onApplicationEvent(mock(ContextRefreshedEvent.class));

            when(request.getMethod()).thenReturn("GET");
            when(request.getRequestURI()).thenReturn("/api/test");
            when(request.getSession(false)).thenReturn(null);
            when(request.getHeader("User-Agent")).thenReturn("test-agent");

            AuthorizationContext ctx = new AuthorizationContext(
                    authentication, null,
                    new ResourceDetails("URL", "/api/test"),
                    "GET",
                    new EnvironmentDetails("10.0.0.1", LocalDateTime.now(), request),
                    new HashMap<>());
            when(contextHandler.create(authentication, request)).thenReturn(ctx);

            RequestAuthorizationContext rac = new RequestAuthorizationContext(request);
            authorizationManager.check(() -> authentication, rac);

            verify(centralAuditFacade).recordAsync(any());
        }
    }

    private Policy buildPolicyWithTarget(String name, Policy.Effect effect,
                                          Policy.PolicySource source, Policy.ApprovalStatus status,
                                          String targetIdentifier, String httpMethod) {
        Policy policy = Policy.builder()
                .name(name)
                .effect(effect)
                .source(source)
                .approvalStatus(status)
                .build();

        PolicyTarget target = PolicyTarget.builder()
                .targetType("URL")
                .targetIdentifier(targetIdentifier)
                .httpMethod(httpMethod)
                .build();
        policy.setTargets(Set.of(target));
        return policy;
    }
}
