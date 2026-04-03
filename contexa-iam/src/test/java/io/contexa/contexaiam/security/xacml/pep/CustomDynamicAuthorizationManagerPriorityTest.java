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
import org.junit.jupiter.api.BeforeEach;
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
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CustomDynamicAuthorizationManagerPriorityTest {

    @Mock private PolicyRetrievalPoint policyRetrievalPoint;
    @Mock private ExpressionAuthorizationManagerResolver managerResolver;
    @Mock private ObjectMapper objectMapper;
    @Mock private ContextHandler contextHandler;
    @Mock private ZeroTrustEventPublisher zeroTrustEventPublisher;
    @Mock private AuthorizationMetrics metricsCollector;
    @Mock private CentralAuditFacade centralAuditFacade;

    private CustomDynamicAuthorizationManager manager;
    private List<String> resolvedExpressions;

    @BeforeEach
    void setUp() {
        manager = new CustomDynamicAuthorizationManager(
                policyRetrievalPoint, managerResolver, objectMapper,
                contextHandler, zeroTrustEventPublisher, metricsCollector, centralAuditFacade,
                new PolicyCombiningEvaluator());
        manager.setCombiningAlgorithm(CombiningAlgorithm.FIRST_APPLICABLE);

        resolvedExpressions = new ArrayList<>();
        AuthorizationManager<RequestAuthorizationContext> dummyManager = mock(AuthorizationManager.class);
        when(managerResolver.resolve(anyString())).thenAnswer(inv -> {
            resolvedExpressions.add(inv.getArgument(0));
            return dummyManager;
        });
    }

    private Policy buildPolicy(Long id, String name, Policy.Effect effect, int priority) {
        return Policy.builder()
                .id(id).name(name).effect(effect).priority(priority)
                .isActive(true).approvalStatus(Policy.ApprovalStatus.APPROVED).build();
    }

    private void addUrlTarget(Policy policy, String path, String httpMethod) {
        PolicyTarget target = PolicyTarget.builder()
                .policy(policy).targetType("URL")
                .targetIdentifier(path).httpMethod(httpMethod).build();
        policy.getTargets().add(target);
    }

    private void addCondition(Policy policy, String expression) {
        PolicyRule rule = PolicyRule.builder().policy(policy).description("rule").build();
        PolicyCondition cond = PolicyCondition.builder().rule(rule).expression(expression).build();
        rule.setConditions(Set.of(cond));
        policy.getRules().add(rule);
    }

    // ── 1. 우선순위 정렬 ────────────────────────────────────────

    @Nested
    @DisplayName("우선순위 기반 정렬")
    class PriorityOrdering {

        @Test
        @DisplayName("초기화 시 정책이 priority ASC 순서로 정렬됨")
        void policiesSortedByPriorityAsc() {
            Policy lowPriority = buildPolicy(1L, "low", Policy.Effect.ALLOW, 500);
            addUrlTarget(lowPriority, "/api/low", null);
            addCondition(lowPriority, "hasAuthority('ROLE_LOW')");

            Policy highPriority = buildPolicy(2L, "high", Policy.Effect.ALLOW, 100);
            addUrlTarget(highPriority, "/api/high", null);
            addCondition(highPriority, "hasAuthority('ROLE_HIGH')");

            Policy medPriority = buildPolicy(3L, "med", Policy.Effect.ALLOW, 300);
            addUrlTarget(medPriority, "/api/med", null);
            addCondition(medPriority, "hasAuthority('ROLE_MED')");

            when(policyRetrievalPoint.findUrlPolicies())
                    .thenReturn(List.of(lowPriority, highPriority, medPriority));

            manager.reload();

            assertThat(resolvedExpressions).containsExactly(
                    "hasAuthority('ROLE_HIGH')",
                    "hasAuthority('ROLE_MED')",
                    "hasAuthority('ROLE_LOW')");
        }

        @Test
        @DisplayName("동일 priority의 정책은 원래 순서를 유지함")
        void samePriorityMaintainsOrder() {
            Policy first = buildPolicy(1L, "first", Policy.Effect.ALLOW, 100);
            addUrlTarget(first, "/api/first", null);
            addCondition(first, "hasAuthority('ROLE_FIRST')");

            Policy second = buildPolicy(2L, "second", Policy.Effect.ALLOW, 100);
            addUrlTarget(second, "/api/second", null);
            addCondition(second, "hasAuthority('ROLE_SECOND')");

            when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of(first, second));

            manager.reload();

            assertThat(resolvedExpressions).hasSize(2);
            assertThat(resolvedExpressions.get(0)).isEqualTo("hasAuthority('ROLE_FIRST')");
            assertThat(resolvedExpressions.get(1)).isEqualTo("hasAuthority('ROLE_SECOND')");
        }
    }

    // ── 2. AI 정책 필터링 ───────────────────────────────────────

    @Nested
    @DisplayName("AI 정책 필터링")
    class AiPolicyFiltering {

        @Test
        @DisplayName("미승인 AI 정책은 초기화 시 제외됨")
        void unapprovedAiPolicySkipped() {
            Policy aiPending = buildPolicy(1L, "ai-pending", Policy.Effect.ALLOW, 100);
            aiPending.setSource(Policy.PolicySource.AI_GENERATED);
            aiPending.setApprovalStatus(Policy.ApprovalStatus.PENDING);
            addUrlTarget(aiPending, "/api/ai", null);
            addCondition(aiPending, "hasAuthority('ROLE_AI')");

            Policy manual = buildPolicy(2L, "manual", Policy.Effect.ALLOW, 200);
            addUrlTarget(manual, "/api/manual", null);
            addCondition(manual, "hasAuthority('ROLE_MANUAL')");

            when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of(aiPending, manual));

            manager.reload();

            assertThat(resolvedExpressions).hasSize(1);
            assertThat(resolvedExpressions.getFirst()).isEqualTo("hasAuthority('ROLE_MANUAL')");
        }

        @Test
        @DisplayName("승인된 AI 정책은 초기화에 포함됨")
        void approvedAiPolicyIncluded() {
            Policy aiApproved = buildPolicy(1L, "ai-approved", Policy.Effect.ALLOW, 100);
            aiApproved.setSource(Policy.PolicySource.AI_GENERATED);
            aiApproved.setApprovalStatus(Policy.ApprovalStatus.APPROVED);
            addUrlTarget(aiApproved, "/api/ai", null);
            addCondition(aiApproved, "hasAuthority('ROLE_AI')");

            when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of(aiApproved));

            manager.reload();

            assertThat(resolvedExpressions).hasSize(1);
        }

        @Test
        @DisplayName("승인되었어도 비활성 AI 정책은 제외됨")
        void inactiveApprovedAiPolicySkipped() {
            Policy aiInactive = buildPolicy(1L, "ai-inactive", Policy.Effect.ALLOW, 100);
            aiInactive.setSource(Policy.PolicySource.AI_GENERATED);
            aiInactive.setApprovalStatus(Policy.ApprovalStatus.APPROVED);
            aiInactive.setIsActive(false);
            addUrlTarget(aiInactive, "/api/ai", null);
            addCondition(aiInactive, "hasAuthority('ROLE_AI')");

            when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of(aiInactive));

            manager.reload();

            assertThat(resolvedExpressions).isEmpty();
        }
    }

    // ── 3. SpEL Expression 구성 ─────────────────────────────────

    @Nested
    @DisplayName("정책에서 SpEL Expression 구성")
    class ExpressionConstruction {

        @Test
        @DisplayName("조건 없는 ALLOW 정책 -> permitAll")
        void noConditionsAllow() {
            Policy policy = buildPolicy(1L, "empty-allow", Policy.Effect.ALLOW, 100);
            String expr = manager.getExpressionFromPolicy(policy);
            assertThat(expr).isEqualTo("permitAll");
        }

        @Test
        @DisplayName("조건 없는 DENY 정책 -> denyAll")
        void noConditionsDeny() {
            Policy policy = buildPolicy(1L, "empty-deny", Policy.Effect.DENY, 100);
            String expr = manager.getExpressionFromPolicy(policy);
            assertThat(expr).isEqualTo("denyAll");
        }

        @Test
        @DisplayName("DENY 정책은 expression을 부정(negation)으로 감쌈")
        void denyPolicyNegation() {
            Policy policy = buildPolicy(1L, "deny-admin", Policy.Effect.DENY, 100);
            addCondition(policy, "hasAuthority('ROLE_ADMIN')");
            String expr = manager.getExpressionFromPolicy(policy);
            assertThat(expr).isEqualTo("!(hasAuthority('ROLE_ADMIN'))");
        }

        @Test
        @DisplayName("여러 조건은 OR로 결합됨")
        void multipleConditionsOr() {
            Policy policy = buildPolicy(1L, "multi", Policy.Effect.ALLOW, 100);
            PolicyRule rule = PolicyRule.builder().policy(policy).build();
            PolicyCondition c1 = PolicyCondition.builder().rule(rule).expression("hasAuthority('ROLE_A')").build();
            PolicyCondition c2 = PolicyCondition.builder().rule(rule).expression("hasAuthority('ROLE_B')").build();
            rule.setConditions(Set.of(c1, c2));
            policy.getRules().add(rule);

            String expr = manager.getExpressionFromPolicy(policy);

            assertThat(expr).contains("hasAuthority('ROLE_A')");
            assertThat(expr).contains("hasAuthority('ROLE_B')");
        }
    }

    // ── 4. 리로드 동작 ──────────────────────────────────────────

    @Nested
    @DisplayName("리로드 동작 검증")
    class ReloadBehavior {

        @Test
        @DisplayName("reload()는 URL 정책 캐시를 초기화하고 다시 로딩함")
        void reloadClearsCacheAndReinitializes() {
            when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of());

            manager.reload();

            verify(policyRetrievalPoint).clearUrlPoliciesCache();
            verify(policyRetrievalPoint).findUrlPolicies();
        }

        @Test
        @DisplayName("reload() 후 새로 추가된 정책이 반영됨")
        void reloadPicksUpNewPolicies() {
            when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of());
            manager.reload();
            assertThat(resolvedExpressions).isEmpty();

            resolvedExpressions.clear();
            Policy newPolicy = buildPolicy(1L, "new", Policy.Effect.ALLOW, 100);
            addUrlTarget(newPolicy, "/api/new", null);
            addCondition(newPolicy, "hasAuthority('ROLE_NEW')");
            when(policyRetrievalPoint.findUrlPolicies()).thenReturn(List.of(newPolicy));

            manager.reload();

            assertThat(resolvedExpressions).hasSize(1);
            assertThat(resolvedExpressions.getFirst()).isEqualTo("hasAuthority('ROLE_NEW')");
        }
    }
}
