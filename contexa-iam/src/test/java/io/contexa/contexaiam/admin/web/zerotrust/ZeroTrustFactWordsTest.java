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
package io.contexa.contexaiam.admin.web.zerotrust;

import io.contexa.contexacore.autonomous.context.decision.DecisionFactsResolver;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.MessageSource;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * K122: the role scope fact a reason cites reads in words in the decision detail, its codes included: an action by its
 * word, a business category the host names by its code in words. The engine's notation stays for every other fact and
 * for any part it reads no notation of.
 */
class ZeroTrustFactWordsTest {

    /** The role scope fact of decision 3a43b81e (7-2, zt7-u34, CHALLENGE) as the engine gave it to the model. */
    private static final String RECORDS = "action EXPORT against the scope group's actions (READ); category"
            + " CUSTOMER_RECORDS against the scope group's categories (CUSTOMER_RECORDS); scope group of 25 other users;"
            + " evidence PROVISIONAL";
    private static final String ROLE_SCOPE = DecisionFactsResolver.ROLE_SCOPE;

    private final MessageSource messages = I18nTestSupport.englishMessageSource();
    private final ZeroTrustFactWords korean = new ZeroTrustFactWords(messages, Locale.KOREAN);
    private final ZeroTrustFactWords english = new ZeroTrustFactWords(messages, Locale.ENGLISH);

    @Test
    @DisplayName("K122: the records notation of the role scope reads in words, no code left, in both languages")
    void theRecordsNotationReadsInWords() {
        assertThat(korean.words(ROLE_SCOPE, RECORDS)).isEqualTo("요청한 행동 내보내기, 범위 그룹의 행동 읽기"
                + " · 요청한 업무 범주 customer records, 범위 그룹의 업무 범주 customer records"
                + " · 범위 그룹의 다른 사용자 25명 · 근거가 아직 잠정적임");
        assertThat(english.words(ROLE_SCOPE, RECORDS)).isEqualTo("requested action Export, the scope group actions Read"
                + " · requested business category customer records, the scope group categories customer records"
                + " · a scope group of 25 other users · evidence still provisional");
        for (ZeroTrustFactWords words : new ZeroTrustFactWords[] {korean, english}) {
            assertThat(words.words(ROLE_SCOPE, RECORDS)).doesNotContainPattern("\\b[A-Z][A-Z0-9]+_[A-Z0-9_]+\\b")
                    .doesNotContain("EXPORT").doesNotContain("PROVISIONAL");
        }
    }

    @Test
    @DisplayName("K122: the older notation's in and out, the denied lists and one other user read in words")
    void theOlderNotationReadsInWords() {
        String older = "action DELETE outside the scope group's actions (READ, WRITE); category PAYROLL within the scope"
                + " group's categories (PAYROLL, HR_RECORDS); action in the scope group's denied actions; category in the"
                + " scope group's denied categories; scope group of 1 other user";

        assertThat(korean.words(ROLE_SCOPE, older)).isEqualTo("요청한 행동 삭제, 범위 그룹의 행동(읽기, 쓰기) 밖"
                + " · 요청한 업무 범주 payroll, 범위 그룹의 업무 범주(payroll, hr records) 안 · 범위 그룹에 막힌 행동"
                + " · 범위 그룹에 막힌 업무 범주 · 범위 그룹의 다른 사용자 1명");
        assertThat(english.words(ROLE_SCOPE, older)).contains("outside the scope group actions (Read, Write)")
                .contains("within the scope group categories (payroll, hr records)")
                .contains("a scope group of 1 other user");
    }

    @Test
    @DisplayName("K122: a part of no known notation, another fact and no value stay as written")
    void whatReadsNoNotationStaysAsWritten() {
        assertThat(korean.words(ROLE_SCOPE, "action EXPORT against the scope group's actions (READ); something new"))
                .isEqualTo("요청한 행동 내보내기, 범위 그룹의 행동 읽기 · something new");
        assertThat(korean.words("RepeatInSession", "5th EXPORT in this session")).isEqualTo("5th EXPORT in this session");
        assertThat(korean.words(ROLE_SCOPE, null)).isNull();
        assertThat(korean.words(null, "first READ of this target in this session"))
                .isEqualTo("first READ of this target in this session");
    }
}
