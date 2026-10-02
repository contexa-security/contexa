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
package io.contexa.contexaiam.security.xacml.pdp.combining;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningEvaluator.CombinedDecision;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import org.springframework.security.authorization.AuthorizationDecision;

import java.util.Arrays;
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

    @Nested
    @DisplayName("NotApplicable(null) 결정 처리")
    class NotApplicableDecisions {

        private List<AuthorizationDecision> decisions(AuthorizationDecision... values) {
            return Arrays.asList(values);
        }

        @Test
        @DisplayName("NotApplicable은 결합에서 제외되고 남은 결정으로 판정")
        void notApplicableIsExcluded() {
            for (CombiningAlgorithm alg : CombiningAlgorithm.values()) {
                assertThat(evaluator.evaluate(decisions(null, ALLOW), alg, NoPolicyDecision.DENY).isGranted())
                        .isTrue();
                assertThat(evaluator.evaluate(decisions(null, DENY), alg, NoPolicyDecision.PERMIT).isGranted())
                        .isFalse();
            }
        }

        @Test
        @DisplayName("FIRST_APPLICABLE은 첫 번째 적용 가능한 결정을 사용")
        void firstApplicableSkipsNotApplicable() {
            assertThat(evaluator.evaluate(decisions(null, DENY, ALLOW),
                    CombiningAlgorithm.FIRST_APPLICABLE, NoPolicyDecision.PERMIT).isGranted()).isFalse();
            assertThat(evaluator.evaluate(decisions(null, ALLOW, DENY),
                    CombiningAlgorithm.FIRST_APPLICABLE, NoPolicyDecision.DENY).isGranted()).isTrue();
        }

        @Test
        @DisplayName("모두 NotApplicable이면 DENY_UNLESS_PERMIT만 거부하고 나머지는 매칭 없음 기본값 적용")
        void allNotApplicable() {
            assertThat(evaluator.evaluate(decisions(null, null),
                    CombiningAlgorithm.DENY_UNLESS_PERMIT, NoPolicyDecision.PERMIT).isGranted()).isFalse();
            assertThat(evaluator.evaluate(decisions(null, null),
                    CombiningAlgorithm.PERMIT_OVERRIDES, NoPolicyDecision.PERMIT).isGranted()).isTrue();
            assertThat(evaluator.evaluate(decisions(null, null),
                    CombiningAlgorithm.DENY_OVERRIDES, NoPolicyDecision.PERMIT).isGranted()).isTrue();
            assertThat(evaluator.evaluate(decisions(null, null),
                    CombiningAlgorithm.FIRST_APPLICABLE, NoPolicyDecision.PERMIT).isGranted()).isTrue();
            assertThat(evaluator.evaluate(decisions(null, null),
                    CombiningAlgorithm.PERMIT_OVERRIDES, NoPolicyDecision.DENY).isGranted()).isFalse();
        }

        @Test
        @DisplayName("매칭 정책이 없으면 모든 알고리즘이 매칭 없음 기본값을 사용")
        void noMatchingPolicyUsesDefault() {
            for (CombiningAlgorithm alg : CombiningAlgorithm.values()) {
                assertThat(evaluator.evaluate(List.of(), alg, NoPolicyDecision.PERMIT).isGranted()).isTrue();
                assertThat(evaluator.evaluate(List.of(), alg, NoPolicyDecision.DENY).isGranted()).isFalse();
            }
        }
    }

    @Nested
    @DisplayName("Combined decision details")
    class CombinedDecisionDetails {

        @Test
        @DisplayName("The no-matching-policy decision is reported as applied only when no policy applied")
        void reportsWhenTheNoPolicyDecisionApplied() {
            CombinedDecision noPolicy = evaluator.combine(List.of(), null, NoPolicyDecision.DENY);
            CombinedDecision notApplicable = evaluator.combine(
                    Arrays.<AuthorizationDecision>asList(null, null), CombiningAlgorithm.PERMIT_OVERRIDES, NoPolicyDecision.PERMIT);
            CombinedDecision denyUnlessPermit = evaluator.combine(
                    Arrays.<AuthorizationDecision>asList(null, null), CombiningAlgorithm.DENY_UNLESS_PERMIT, NoPolicyDecision.PERMIT);
            CombinedDecision applied = evaluator.combine(
                    Arrays.asList(null, DENY), CombiningAlgorithm.FIRST_APPLICABLE, NoPolicyDecision.PERMIT);

            assertThat(noPolicy.decision().isGranted()).isFalse();
            assertThat(noPolicy.noPolicyDecisionApplied()).isTrue();
            assertThat(noPolicy.algorithm()).isEqualTo(CombiningAlgorithm.FIRST_APPLICABLE);
            assertThat(noPolicy.noPolicyDecision()).isEqualTo(NoPolicyDecision.DENY);
            assertThat(notApplicable.decision().isGranted()).isTrue();
            assertThat(notApplicable.noPolicyDecisionApplied()).isTrue();
            assertThat(denyUnlessPermit.decision().isGranted()).isFalse();
            assertThat(denyUnlessPermit.noPolicyDecisionApplied()).isFalse();
            assertThat(applied.decision().isGranted()).isFalse();
            assertThat(applied.noPolicyDecisionApplied()).isFalse();
        }

        @Test
        @DisplayName("ALLOW yields Permit or Deny and DENY yields Deny or NotApplicable")
        void appliesPolicyEffects() {
            assertThat(PolicyCombiningEvaluator.applyEffect(Policy.Effect.ALLOW, true).isGranted()).isTrue();
            assertThat(PolicyCombiningEvaluator.applyEffect(Policy.Effect.ALLOW, false).isGranted()).isFalse();
            assertThat(PolicyCombiningEvaluator.applyEffect(Policy.Effect.DENY, true).isGranted()).isFalse();
            assertThat(PolicyCombiningEvaluator.applyEffect(Policy.Effect.DENY, false)).isNull();
        }
    }
}
