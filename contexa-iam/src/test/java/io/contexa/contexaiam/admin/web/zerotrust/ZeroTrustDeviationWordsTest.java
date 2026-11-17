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

import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.Test;
import org.springframework.context.MessageSource;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * K26, K27: the comparison with the usual reads in plain words of the language, the request's value and the usual one,
 * never in the engine's notation ({@code Mon}, {@code WRITE}, {@code CRITICAL}, {@code PASSWORD+ONE_TIME_CODE}).
 */
class ZeroTrustDeviationWordsTest {

    private final MessageSource messages = I18nTestSupport.englishMessageSource();
    private final ZeroTrustDeviationWords korean = new ZeroTrustDeviationWords(messages, Locale.KOREAN);
    private final ZeroTrustDeviationWords english = new ZeroTrustDeviationWords(messages, Locale.ENGLISH);

    @Test
    void theRequestsValueReadsInWords() {
        assertThat(korean.current("DAY", "Mon")).isEqualTo("월요일");
        assertThat(english.current("DAY", "Mon")).isEqualTo("Monday");
        assertThat(korean.current("ACTION", "WRITE")).isEqualTo("쓰기");
        assertThat(english.current("ACTION", "EXPORT")).isEqualTo("Export");
        assertThat(korean.current("RESOURCE_CLASS", "CRITICAL")).isEqualTo("중요");
        assertThat(korean.current("LOGIN_METHOD", "PASSWORD+ONE_TIME_CODE")).isEqualTo("비밀번호 + 일회용 코드");
        assertThat(english.current("LOGIN_METHOD", "PASSWORD+ONE_TIME_CODE")).isEqualTo("Password + One-time code");
        assertThat(korean.current("TIME", "03")).isEqualTo("03시");
        assertThat(english.current("TIME", "03")).isEqualTo("03:00");
        assertThat(korean.current("DEVICE", "Chrome/140 on WINDOWS")).isEqualTo("Chrome/140 · Windows");
        assertThat(korean.current("SIZE", "1,200 items")).isEqualTo("1,200건");
        assertThat(english.current("SIZE", "1,200 items")).isEqualTo("1,200 items");
        assertThat(korean.current("RATE", "5 requests in the last 60 min")).isEqualTo("최근 60분 요청 5건");
        assertThat(korean.current("RATE", "5 requests in the last 60 min of this session"))
                .isEqualTo("최근 60분 이 세션의 요청 5건");
        assertThat(korean.current("NETWORK", "203.0.113.0/24")).as("a network band is its own name")
                .isEqualTo("203.0.113.0/24");
        assertThat(korean.current("ACTION", "SOMETHING_NEW")).as("a value no message names stays as written")
                .isEqualTo("SOMETHING_NEW");
    }

    @Test
    void theUsualValueReadsInWordsWithHowOftenTheRequestsValueWasSeen() {
        Map<String, Object> time = deviation("TIME", "03", Map.of("usualValues", List.of("09", "10", "11", "14"),
                "seen", 0, "of", 25));
        Map<String, Object> day = deviation("DAY", "Sun", Map.of("usualValues", List.of("Mon", "Tue", "Wed")));
        Map<String, Object> device = deviation("DEVICE", "Chrome/140 on WINDOWS",
                Map.of("usualValues", List.of("Safari/17 on MAC"), "seen", 0, "of", 46));
        Map<String, Object> actions = deviation("ACTION", "WRITE", Map.of("usualValues",
                List.of("READ", "EXPORT", "DELETE", "ADMIN", "EXECUTE", "WRITE"), "usualMore", 1));

        assertThat(korean.usual("TIME", time)).isEqualTo("09~11시, 14시 · 이번 값은 25번 중 0번");
        assertThat(english.usual("TIME", time)).isEqualTo("09:00–11:59, 14:00 · this value 0 of 25 times");
        assertThat(korean.usual("DAY", day)).isEqualTo("월, 화, 수");
        assertThat(korean.usual("DEVICE", device)).isEqualTo("Safari/17 · macOS · 이번 값은 46번 중 0번");
        assertThat(korean.usual("ACTION", actions)).as("four named, the rest counted")
                .isEqualTo("읽기, 내보내기, 삭제, 관리 작업 외 3개");
    }

    /** A size and a rate say their usual value in the engine's sentence, kept before K27 as well. */
    @Test
    void theUsualSizeAndRateTheEngineWroteReadInWords() {
        assertThat(korean.usual("SIZE", deviation("SIZE", "120 items",
                Map.of("usual", "up to 29 items per export (median 10, 3 exports)"))))
                .isEqualTo("내보내기 한 번에 최대 29건 (중앙값 10건, 3번)");
        assertThat(korean.usual("RATE", deviation("RATE", "9 requests in the last 60 min",
                Map.of("usual", "median 2, 95th percentile 6 in the 60 min up to a request"))))
                .isEqualTo("60분마다 중앙값 2건, 상위 5% 경계 6건");
        assertThat(korean.usual("LOGIN_METHOD", deviation("LOGIN_METHOD", "PASSWORD+ONE_TIME_CODE",
                Map.of("usual", "PASSWORD")))).isEqualTo("비밀번호");
    }

    /** K27: a decision stored before the usual values were kept has none to show for the other dimensions. */
    @Test
    void aDecisionStoredBeforeKeepsNoUsualValue() {
        List<Map<String, Object>> worded = korean.words(List.of(deviation("DAY", "Mon", Map.of())));

        assertThat(worded).singleElement().satisfies(row -> {
            assertThat(row.get("currentText")).isEqualTo("월요일");
            assertThat(row.get("usualText")).isNull();
            assertThat(row.get("current")).as("the record stays as kept").isEqualTo("Mon");
        });
    }

    private static Map<String, Object> deviation(String dimension, String current, Map<String, Object> more) {
        Map<String, Object> deviation = new HashMap<>(more);
        deviation.put("dimension", dimension);
        deviation.put("current", current);
        deviation.put("compared", true);
        deviation.put("different", true);
        return deviation;
    }
}
