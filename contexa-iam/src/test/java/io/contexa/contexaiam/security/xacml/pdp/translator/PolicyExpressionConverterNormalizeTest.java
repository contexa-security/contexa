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
package io.contexa.contexaiam.security.xacml.pdp.translator;

import org.junit.jupiter.api.Test;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CF-08: a policy condition keeps its structure when bare authority names are wrapped, so grouping and operator
 * precedence mean what the author wrote.
 */
class PolicyExpressionConverterNormalizeTest {

    @Test
    void groupingAndPrecedenceAreKept() {
        String condition = "hasRole('ADMIN') and (isAllowed() or isPendingAnalysis())";

        String normalized = PolicyExpressionConverter.normalize(condition);

        assertThat(normalized).isEqualTo(condition);
        // Not an administrator, analysis pending: the condition must not hold.
        assertThat(evaluate(normalized, Set.of(), false, true)).isFalse();
        assertThat(evaluate(normalized, Set.of("ADMIN"), false, true)).isTrue();
    }

    @Test
    void nestedCallsWithAndInsideParenthesesStayIntact() {
        String condition = "!isDelegatedAgent() or (delegationAllowsOperation('export') and delegationAllowsResource('/a'))";

        assertThat(PolicyExpressionConverter.normalize(condition)).isEqualTo(condition);
    }

    @Test
    void bareAuthorityNamesAreWrappedAndEverythingElseIsLeftAlone() {
        assertThat(PolicyExpressionConverter.normalize("ROLE_ADMIN")).isEqualTo("hasAuthority('ROLE_ADMIN')");
        assertThat(PolicyExpressionConverter.normalize("ROLE_ADMIN or hasRole('MANAGER')"))
                .isEqualTo("hasAuthority('ROLE_ADMIN') or hasRole('MANAGER')");
        assertThat(PolicyExpressionConverter.normalize("ROLE_A OR (ROLE_B AND hasActionIn('ALLOW', 'CHALLENGE'))"))
                .isEqualTo("hasAuthority('ROLE_A') OR (hasAuthority('ROLE_B') AND hasActionIn('ALLOW', 'CHALLENGE'))");
        assertThat(PolicyExpressionConverter.normalize("T(java.time.DayOfWeek).MONDAY == T(java.time.LocalDate).now().getDayOfWeek()"))
                .isEqualTo("T(java.time.DayOfWeek).MONDAY == T(java.time.LocalDate).now().getDayOfWeek()");
        assertThat(PolicyExpressionConverter.normalize("hasAuthority('it''s ROLE_X') and ROLE_Y"))
                .isEqualTo("hasAuthority('it''s ROLE_X') and hasAuthority('ROLE_Y')");
        assertThat(PolicyExpressionConverter.normalize("permitAll")).isEqualTo("permitAll");
        assertThat(PolicyExpressionConverter.normalize(" ")).isEqualTo("permitAll");
    }

    /** Evaluates the condition against a root with the given roles and zero trust state. */
    private static boolean evaluate(String expression, Set<String> roles, boolean allowed, boolean pending) {
        StandardEvaluationContext context = new StandardEvaluationContext(new Root(roles, allowed, pending));
        return Boolean.TRUE.equals(new SpelExpressionParser().parseExpression(expression).getValue(context, Boolean.class));
    }

    public record Root(Set<String> roles, boolean allowed, boolean pending) {

        public boolean hasRole(String role) {
            return roles.contains(role);
        }

        public boolean isAllowed() {
            return allowed;
        }

        public boolean isPendingAnalysis() {
            return pending;
        }
    }
}
