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

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PolicyExpressionValidatorTest {

    @Nested
    @DisplayName("Rejected constructs")
    class Rejected {

        @ParameterizedTest
        @ValueSource(strings = {
                "T(java.lang.Runtime).getRuntime().exec('calc')",
                "T(java.lang.System).exit(0)",
                "T(java.lang.Class).forName('java.lang.Runtime')",
                "T(int) != null",
                "new java.lang.ProcessBuilder('calc').start()",
                "new String('x') != null",
                "''.getClass().forName('java.lang.Runtime')",
                "''.class.forName('java.lang.Runtime')",
                "#this.class.classLoader != null",
                "''['class'] != null",
                "@systemSettingsService.getSettings() != null",
                "authentication.authenticated = false",
                "principal.toString().getClass() != null",
                "Runtime.getRuntime()",
                "java.lang.System.exit(0)",
                "exec('malicious')",
                "T(java.time.LocalTime).forName('java.lang.Runtime') != null"
        })
        void forbiddenConstructsAreRejected(String expression) {
            assertThat(PolicyExpressionValidator.findViolation(expression)).isPresent();
            assertThatThrownBy(() -> PolicyExpressionValidator.validate(expression))
                    .isInstanceOf(UnsafePolicyExpressionException.class)
                    .satisfies(e -> assertThat(((UnsafePolicyExpressionException) e).isParseFailure()).isFalse())
                    .satisfies(e -> assertThat(((UnsafePolicyExpressionException) e).getMessageKey())
                            .isEqualTo("msg.policy.spel.dangerous"));
        }

        @Test
        @DisplayName("Unparseable and blank expressions are rejected as invalid")
        void unparseableExpressionIsInvalid() {
            for (String expression : new String[]{"hasRole('ADMIN') and", "( )", " "}) {
                assertThatThrownBy(() -> PolicyExpressionValidator.validate(expression))
                        .isInstanceOf(UnsafePolicyExpressionException.class)
                        .satisfies(e -> assertThat(((UnsafePolicyExpressionException) e).getMessageKey())
                                .isEqualTo("msg.policy.spel.invalid"));
            }
        }

        @Test
        @DisplayName("Policy validation reports the first rejected condition")
        void policyWithDangerousConditionIsRejected() {
            Policy policy = Policy.builder().name("p").effect(Policy.Effect.ALLOW).build();
            PolicyRule rule = PolicyRule.builder().policy(policy).build();
            rule.setConditions(Set.of(
                    PolicyCondition.builder().rule(rule).expression("T(java.lang.Runtime).getRuntime() != null").build()));
            policy.getRules().add(rule);

            assertThatThrownBy(() -> PolicyExpressionValidator.validatePolicy(policy))
                    .isInstanceOf(UnsafePolicyExpressionException.class)
                    .hasMessageContaining("java.lang.Runtime");
        }

        @Test
        @DisplayName("A template parameter that breaks out of its quotes is rejected after formatting")
        void injectedTemplateParameterIsRejected() {
            String formatted = String.format("hasIpAddress(%s)",
                    "'10.0.0.1') or T(java.lang.Runtime).getRuntime().exec('calc') != null or hasIpAddress('10.0.0.2'");

            assertThat(PolicyExpressionValidator.findViolation(formatted)).isPresent();
        }

        @Test
        @DisplayName("Dangerous condition templates are rejected")
        void dangerousTemplateIsRejected() {
            assertThat(PolicyExpressionValidator.findTemplateViolation(
                    "T(java.lang.Runtime).getRuntime().exec(%s) != null")).isPresent();
            assertThatThrownBy(() -> PolicyExpressionValidator.validateTemplate("''.getClass().forName(%s)"))
                    .isInstanceOf(UnsafePolicyExpressionException.class);
        }
    }

    @Nested
    @DisplayName("Accepted expressions")
    class Accepted {

        @ParameterizedTest
        @ValueSource(strings = {
                "permitAll",
                "denyAll",
                "isAuthenticated()",
                "isFullyAuthenticated()",
                "isAnonymous()",
                "hasRole('ADMIN')",
                "hasAnyRole('ADMIN', 'MANAGER')",
                "hasAuthority('ROLE_ADMIN')",
                "hasAnyAuthority('ROLE_ADMIN','ROLE_USER')",
                "ROLE_ADMIN",
                "ROLE_ADMIN or hasRole('MANAGER')",
                "hasIpAddress('192.168.1.0/24')",
                "hasPermission(#id, 'DOCUMENT', 'READ')",
                "hasPermission(#document, 'DOCUMENT_READ')",
                "#ai.isAllowed()",
                "#ai.hasActionIn('ALLOW','CHALLENGE')",
                "#ai.hasActionOrDefault('ALLOW', 'ALLOW', 'MONITOR')",
                "(hasAuthority('ROLE_USER')) and (#ai.isAllowed())",
                "#request.remoteAddr == '127.0.0.1'",
                "#isBusinessHours()",
                "principal.username == #owner",
                "T(java.time.LocalTime).now().hour >= 9 && T(java.time.LocalTime).now().hour <= 18",
                "T(java.time.LocalDate).now().dayOfWeek != T(java.time.DayOfWeek).SUNDAY"
        })
        void safeExpressionsAreAccepted(String expression) {
            assertThat(PolicyExpressionValidator.findViolation(expression)).isEmpty();
            assertThatCode(() -> PolicyExpressionValidator.validate(expression)).doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Condition templates with format placeholders are accepted")
        void templatesWithPlaceholdersAreAccepted() {
            assertThat(PolicyExpressionValidator.findTemplateViolation("hasIpAddress(%s)")).isEmpty();
            assertThat(PolicyExpressionValidator.findTemplateViolation("#ai.hasAction(%1$s)")).isEmpty();
            assertThat(PolicyExpressionValidator.findTemplateViolation("#count > %d")).isEmpty();
        }
    }
}
