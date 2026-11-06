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

import io.contexa.contexaiam.security.xacml.pdp.evaluation.AuthorityProbe.Outcome;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.expression.spel.standard.SpelExpressionParser;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.contexa.contexaiam.security.xacml.pdp.evaluation.AuthorityProbe.ALWAYS_TRUE_NAME;
import static org.assertj.core.api.Assertions.assertThat;

class SpelLiteralTest {

    @ParameterizedTest
    @ValueSource(strings = {"ROLE_ADMIN", "O'Neil", "R&D \"Ops\" <West>", "''", "'", "A$1\\B", ALWAYS_TRUE_NAME, "관리자"})
    @DisplayName("a name is one literal that holds the name as it is")
    void aNameIsOneLiteral(String name) {
        Object value = new SpelExpressionParser().parseExpression(SpelLiteral.quote(name)).getValue();

        assertThat(value).isEqualTo(name);
    }

    @Test
    @DisplayName("a name with no quote is written as it always was, so stored expressions stay as they are")
    void aNameWithNoQuoteIsWrittenAsBefore() {
        assertThat(SpelLiteral.hasAuthority("ROLE_ADMIN")).isEqualTo("hasAuthority('ROLE_ADMIN')");
        assertThat(SpelLiteral.quote("URL_/api/x$1\\y")).isEqualTo("'URL_/api/x$1\\y'");
    }

    @Test
    @DisplayName("a name that would end its literal asks for itself only and is never always true")
    void aNameThatWouldEndItsLiteralAsksForItselfOnly() {
        String expression = SpelLiteral.hasAuthority(ALWAYS_TRUE_NAME);

        Outcome nobody = AuthorityProbe.evaluate(expression);
        assertThat(nobody.granted()).isFalse();
        assertThat(nobody.asked()).containsExactly(ALWAYS_TRUE_NAME);
        assertThat(AuthorityProbe.evaluate(expression, "R&D", "Ops").granted()).isFalse();
        assertThat(AuthorityProbe.evaluate(expression, ALWAYS_TRUE_NAME).granted()).isTrue();
    }

    @Test
    @DisplayName("a literal is read back as the name it holds")
    void aLiteralIsReadBack() {
        String expression = SpelLiteral.hasAuthority("O'Neil") + " or " + SpelLiteral.hasAuthority("B")
                + " or " + SpelLiteral.hasAuthority(ALWAYS_TRUE_NAME);
        Matcher matcher = Pattern.compile("hasAuthority\\(" + SpelLiteral.PATTERN + "\\)").matcher(expression);
        List<String> names = new ArrayList<>();
        while (matcher.find()) {
            names.add(SpelLiteral.unquote(matcher.group(1)));
        }

        assertThat(names).containsExactly("O'Neil", "B", ALWAYS_TRUE_NAME);
    }
}
