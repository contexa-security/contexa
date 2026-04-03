package io.contexa.contexaiam.security.xacml.pep;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.metrics.AuthorizationMetrics;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningEvaluator;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CustomDynamicAuthorizationManagerCombiningTest {

    @Mock private PolicyRetrievalPoint policyRetrievalPoint;
    @Mock private ExpressionAuthorizationManagerResolver managerResolver;
    @Mock private ObjectMapper objectMapper;
    @Mock private ContextHandler contextHandler;
    @Mock private ZeroTrustEventPublisher zeroTrustEventPublisher;
    @Mock private AuthorizationMetrics metricsCollector;
    @Mock private CentralAuditFacade centralAuditFacade;

    private CustomDynamicAuthorizationManager createManager(CombiningAlgorithm algorithm) {
        CustomDynamicAuthorizationManager manager = new CustomDynamicAuthorizationManager(
                policyRetrievalPoint, managerResolver, objectMapper,
                contextHandler, zeroTrustEventPublisher, metricsCollector, centralAuditFacade,
                new PolicyCombiningEvaluator());
        manager.setCombiningAlgorithm(algorithm);
        return manager;
    }

    private Policy buildPolicy(Long id, String name, Policy.Effect effect, int priority,
                                String path, String condition) {
        Policy policy = Policy.builder().id(id).name(name).effect(effect).priority(priority)
                .isActive(true).approvalStatus(Policy.ApprovalStatus.APPROVED).build();
        PolicyTarget target = PolicyTarget.builder()
                .policy(policy).targetType("URL").targetIdentifier(path).build();
        policy.getTargets().add(target);
        PolicyRule rule = PolicyRule.builder().policy(policy).build();
        PolicyCondition cond = PolicyCondition.builder().rule(rule).expression(condition).build();
        rule.setConditions(Set.of(cond));
        policy.getRules().add(rule);
        return policy;
    }

    // ── 1. 알고리즘별 초기화 검증 ───────────────────────────────

    @Nested
    @DisplayName("결합 알고리즘별 정책 로딩")
    class AlgorithmInitialization {

        @Test
        @DisplayName("DENY_OVERRIDES로 초기화 시 모든 정책이 로딩됨")
        @SuppressWarnings("unchecked")
        void denyOverridesLoadsAll() {
            Policy p1 = buildPolicy(1L, "allow", Policy.Effect.ALLOW, 100, "/api/test", "permitAll");
            Policy p2 = buildPolicy(2L, "deny", Policy.Effect.DENY, 200, "/api/test", "denyAll");

            when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of(p1, p2));
            List<String> resolved = new ArrayList<>();
            AuthorizationManager<RequestAuthorizationContext> dummy = mock(AuthorizationManager.class);
            when(managerResolver.resolve(anyString())).thenAnswer(inv -> {
                resolved.add(inv.getArgument(0));
                return dummy;
            });

            CustomDynamicAuthorizationManager manager = createManager(CombiningAlgorithm.DENY_OVERRIDES);
            manager.reload();

            assertThat(resolved).hasSize(2);
        }

        @Test
        @DisplayName("FIRST_APPLICABLE로 초기화 시 priority 정렬 적용됨")
        @SuppressWarnings("unchecked")
        void firstApplicableSortsByPriority() {
            Policy low = buildPolicy(1L, "low", Policy.Effect.ALLOW, 500, "/api/low", "permitAll");
            Policy high = buildPolicy(2L, "high", Policy.Effect.DENY, 100, "/api/high", "denyAll");

            when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of(low, high));
            List<String> resolved = new ArrayList<>();
            AuthorizationManager<RequestAuthorizationContext> dummy = mock(AuthorizationManager.class);
            when(managerResolver.resolve(anyString())).thenAnswer(inv -> {
                resolved.add(inv.getArgument(0));
                return dummy;
            });

            CustomDynamicAuthorizationManager manager = createManager(CombiningAlgorithm.FIRST_APPLICABLE);
            manager.reload();

            // high priority (100) should be resolved first
            assertThat(resolved.get(0)).isEqualTo("!(denyAll)");
            assertThat(resolved.get(1)).isEqualTo("permitAll");
        }
    }

    // ── 2. Expression 변환은 알고리즘과 무관하게 동일 ────────────

    @Nested
    @DisplayName("알고리즘 무관 Expression 변환")
    class ExpressionConversion {

        @Test
        @DisplayName("DENY_OVERRIDES에서도 DENY 정책의 expression이 부정으로 래핑됨")
        void denyExpressionNegated() {
            CustomDynamicAuthorizationManager manager = createManager(CombiningAlgorithm.DENY_OVERRIDES);
            Policy denyPolicy = buildPolicy(1L, "deny", Policy.Effect.DENY, 100, "/api/test", "hasAuthority('ROLE_ADMIN')");

            String expr = manager.getExpressionFromPolicy(denyPolicy);

            assertThat(expr).isEqualTo("!(hasAuthority('ROLE_ADMIN'))");
        }

        @Test
        @DisplayName("PERMIT_OVERRIDES에서도 ALLOW 정책의 expression은 그대로")
        void allowExpressionUnchanged() {
            CustomDynamicAuthorizationManager manager = createManager(CombiningAlgorithm.PERMIT_OVERRIDES);
            Policy allowPolicy = buildPolicy(1L, "allow", Policy.Effect.ALLOW, 100, "/api/test", "hasAuthority('ROLE_USER')");

            String expr = manager.getExpressionFromPolicy(allowPolicy);

            assertThat(expr).isEqualTo("hasAuthority('ROLE_USER')");
        }
    }

    // ── 3. AI 정책 필터링은 알고리즘과 무관 ─────────────────────

    @Nested
    @DisplayName("AI 정책 필터링은 알고리즘과 무관")
    class AiPolicyFiltering {

        @Test
        @DisplayName("미승인 AI 정책은 어떤 알고리즘에서도 제외됨")
        @SuppressWarnings("unchecked")
        void unapprovedAiSkippedInAllAlgorithms() {
            Policy aiPending = buildPolicy(1L, "ai", Policy.Effect.ALLOW, 100, "/api/ai", "permitAll");
            aiPending.setSource(Policy.PolicySource.AI_GENERATED);
            aiPending.setApprovalStatus(Policy.ApprovalStatus.PENDING);

            Policy manual = buildPolicy(2L, "manual", Policy.Effect.ALLOW, 200, "/api/manual", "permitAll");

            for (CombiningAlgorithm alg : CombiningAlgorithm.values()) {
                when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of(aiPending, manual));
                List<String> resolved = new ArrayList<>();
                AuthorizationManager<RequestAuthorizationContext> dummy = mock(AuthorizationManager.class);
                when(managerResolver.resolve(anyString())).thenAnswer(inv -> {
                    resolved.add(inv.getArgument(0));
                    return dummy;
                });

                CustomDynamicAuthorizationManager manager = createManager(alg);
                manager.reload();

                assertThat(resolved).hasSize(1);
                resolved.clear();
            }
        }
    }
}
