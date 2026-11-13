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
package io.contexa.contexaiam.security.xacml.pdp.evaluation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * D68: the seed condition template {@code #isBusinessHours()} named a function no evaluation context had, and the
 * validator let any function through, so such a condition was saved and then failed on every request it covered.
 */
class PolicyFunctionsTest {

    @ParameterizedTest
    @CsvSource({
            "2026-11-13T09:00, true",
            "2026-11-13T17:59, true",
            "2026-11-13T18:00, false",
            "2026-11-13T08:59, false",
            "2026-11-14T10:00, false",
            "2026-11-15T10:00, false",
            "2026-11-16T10:00, true"
    })
    @DisplayName("business hours are Monday to Friday, from 09:00 up to 18:00")
    void businessHours(String time, boolean expected) {
        assertThat(PolicyFunctions.isBusinessHours(LocalDateTime.parse(time))).isEqualTo(expected);
    }

    @Test
    @DisplayName("a context the functions are registered on evaluates #isBusinessHours()")
    void aContextEvaluatesTheFunction() {
        StandardEvaluationContext context = new StandardEvaluationContext();
        PolicyFunctions.register(context);
        PolicyExpressionSandbox.apply(context);

        Object value = new SpelExpressionParser().parseExpression("#isBusinessHours()").getValue(context);

        assertThat(value).isEqualTo(PolicyFunctions.isBusinessHours());
    }

    @Test
    @DisplayName("the validator accepts the registered function and refuses any other, naming the ones there are")
    void theValidatorKnowsTheFunctions() {
        assertThat(PolicyExpressionValidator.findViolation("#isBusinessHours()")).isEmpty();
        assertThat(PolicyExpressionValidator.findViolation("hasRole('USER') and #isBusinessHours()")).isEmpty();
        assertThat(PolicyExpressionValidator.findViolation("#isBusinesHours()"))
                .hasValueSatisfying(reason -> assertThat(reason)
                        .contains("#isBusinesHours").contains("isBusinessHours"));
        assertThat(PolicyExpressionValidator.findViolation("#exec('x')")).isPresent();
        // A variable is no function call: #request and #ai stay as they were.
        assertThat(PolicyExpressionValidator.findViolation("#request.remoteAddr == '127.0.0.1'")).isEmpty();
        assertThat(PolicyExpressionValidator.findViolation("#ai.isAllowed()")).isEmpty();
    }
}
