package io.contexa.contexaiam.security.xacml.pdp.combining;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.authorization.AuthorizationDecision;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PolicyCombiningEvaluatorTest {

    private PolicyCombiningEvaluator evaluator;

    private static final AuthorizationDecision ALLOW = new AuthorizationDecision(true);
    private static final AuthorizationDecision DENY = new AuthorizationDecision(false);

    @BeforeEach
    void setUp() {
        evaluator = new PolicyCombiningEvaluator();
    }

    @Nested
    @DisplayName("DENY_OVERRIDES 알고리즘")
    class DenyOverrides {

        @Test
        @DisplayName("모든 정책이 ALLOW이면 결과는 ALLOW")
        void allAllowResultsInAllow() {
            AuthorizationDecision result = evaluator.evaluate(
                    List.of(ALLOW, ALLOW, ALLOW), CombiningAlgorithm.DENY_OVERRIDES);
            assertThat(result.isGranted()).isTrue();
        }

        @Test
        @DisplayName("DENY가 하나라도 있으면 결과는 DENY")
        void anyDenyResultsInDeny() {
            AuthorizationDecision result = evaluator.evaluate(
                    List.of(ALLOW, DENY, ALLOW), CombiningAlgorithm.DENY_OVERRIDES);
            assertThat(result.isGranted()).isFalse();
        }

        @Test
        @DisplayName("DENY가 첫 번째여도 결과는 DENY")
        void denyFirstStillDenies() {
            AuthorizationDecision result = evaluator.evaluate(
                    List.of(DENY, ALLOW), CombiningAlgorithm.DENY_OVERRIDES);
            assertThat(result.isGranted()).isFalse();
        }
    }

    @Nested
    @DisplayName("PERMIT_OVERRIDES 알고리즘")
    class PermitOverrides {

        @Test
        @DisplayName("ALLOW가 하나라도 있으면 결과는 ALLOW")
        void anyAllowResultsInAllow() {
            AuthorizationDecision result = evaluator.evaluate(
                    List.of(DENY, ALLOW, DENY), CombiningAlgorithm.PERMIT_OVERRIDES);
            assertThat(result.isGranted()).isTrue();
        }

        @Test
        @DisplayName("모든 정책이 DENY이면 결과는 DENY")
        void allDenyResultsInDeny() {
            AuthorizationDecision result = evaluator.evaluate(
                    List.of(DENY, DENY), CombiningAlgorithm.PERMIT_OVERRIDES);
            assertThat(result.isGranted()).isFalse();
        }
    }

    @Nested
    @DisplayName("FIRST_APPLICABLE 알고리즘")
    class FirstApplicable {

        @Test
        @DisplayName("첫 번째 결정이 반환됨")
        void firstDecisionReturned() {
            AuthorizationDecision result = evaluator.evaluate(
                    List.of(DENY, ALLOW), CombiningAlgorithm.FIRST_APPLICABLE);
            assertThat(result.isGranted()).isFalse();
        }

        @Test
        @DisplayName("첫 번째가 ALLOW이면 나머지 무시")
        void firstAllowIgnoresRest() {
            AuthorizationDecision result = evaluator.evaluate(
                    List.of(ALLOW, DENY), CombiningAlgorithm.FIRST_APPLICABLE);
            assertThat(result.isGranted()).isTrue();
        }
    }

    @Nested
    @DisplayName("DENY_UNLESS_PERMIT 알고리즘")
    class DenyUnlessPermit {

        @Test
        @DisplayName("명시적 ALLOW가 없으면 DENY")
        void noAllowResultsInDeny() {
            AuthorizationDecision result = evaluator.evaluate(
                    List.of(DENY, DENY), CombiningAlgorithm.DENY_UNLESS_PERMIT);
            assertThat(result.isGranted()).isFalse();
        }

        @Test
        @DisplayName("ALLOW가 있으면 ALLOW")
        void allowPresent() {
            AuthorizationDecision result = evaluator.evaluate(
                    List.of(DENY, ALLOW), CombiningAlgorithm.DENY_UNLESS_PERMIT);
            assertThat(result.isGranted()).isTrue();
        }
    }

    @Nested
    @DisplayName("엣지 케이스")
    class EdgeCases {

        @Test
        @DisplayName("빈 결정 목록이면 ALLOW (정책 없음 = 허용)")
        void emptyDecisions() {
            AuthorizationDecision result = evaluator.evaluate(
                    List.of(), CombiningAlgorithm.DENY_OVERRIDES);
            assertThat(result.isGranted()).isTrue();
        }

        @Test
        @DisplayName("단일 결정은 모든 알고리즘에서 동일 결과")
        void singleDecision() {
            for (CombiningAlgorithm alg : CombiningAlgorithm.values()) {
                AuthorizationDecision allow = evaluator.evaluate(List.of(ALLOW), alg);
                assertThat(allow.isGranted()).isTrue();
                AuthorizationDecision deny = evaluator.evaluate(List.of(DENY), alg);
                assertThat(deny.isGranted()).isFalse();
            }
        }
    }
}
