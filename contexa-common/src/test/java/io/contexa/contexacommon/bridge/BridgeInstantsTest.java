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
package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.bridge.BridgeInstants;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class BridgeInstantsTest {

    private static final Instant AT = Instant.parse("2026-03-20T09:53:20Z");

    @Test
    @DisplayName("시각, 날짜, epoch 초와 밀리초(숫자와 숫자 글), ISO-8601 글을 같은 시각으로 읽는다")
    void everyFormOfTheSameTimeReadsAsTheSameInstant() {
        assertThat(BridgeInstants.parse(AT)).isEqualTo(AT);
        assertThat(BridgeInstants.parse(Date.from(AT))).isEqualTo(AT);
        assertThat(BridgeInstants.parse(AT.getEpochSecond())).isEqualTo(AT);
        assertThat(BridgeInstants.parse((int) AT.getEpochSecond())).isEqualTo(AT);
        assertThat(BridgeInstants.parse(AT.toEpochMilli())).isEqualTo(AT);
        assertThat(BridgeInstants.parse(String.valueOf(AT.getEpochSecond()))).isEqualTo(AT);
        assertThat(BridgeInstants.parse(" " + AT.toEpochMilli() + " ")).isEqualTo(AT);
        assertThat(BridgeInstants.parse("2026-03-20T09:53:20Z")).isEqualTo(AT);
        assertThat(BridgeInstants.parse("2026-03-20T18:53:20+09:00")).isEqualTo(AT);
    }

    @Test
    @DisplayName("시각을 말하지 않는 값은 시각이 없다")
    void aValueThatStatesNoTimeHasNone() {
        assertThat(BridgeInstants.parse(null)).isNull();
        assertThat(BridgeInstants.parse(" ")).isNull();
        assertThat(BridgeInstants.parse("yesterday")).isNull();
        assertThat(BridgeInstants.parse("2026-03-20 09:53:20")).isNull();
        assertThat(BridgeInstants.parse("99999999999999999999999")).isNull();
        assertThat(BridgeInstants.parse(Boolean.TRUE)).isNull();
    }

    @Test
    @DisplayName("레거시 날짜 숫자 글은 밀리초로 읽혀 미래가 되고 미래 판정에 걸린다")
    void legacyDateDigitsReadAsMillisecondsLieInTheFuture() {
        Instant read = BridgeInstants.parse("20261125103000");

        assertThat(read).isAfter(Instant.parse("2600-01-01T00:00:00Z"));
        assertThat(BridgeInstants.isFuture(read)).isTrue();
    }

    @Test
    @DisplayName("이미 일어난 시각은 시계 차이 60초까지 미래여도 받는다")
    void aTimeWithinTheClockSkewIsNoFuture() {
        Instant now = Instant.parse("2026-11-25T10:00:00Z");

        assertThat(BridgeInstants.isFuture(now.plusSeconds(60), now)).isFalse();
        assertThat(BridgeInstants.isFuture(now.plusSeconds(61), now)).isTrue();
        assertThat(BridgeInstants.isFuture(now.minusSeconds(3_600), now)).isFalse();
        assertThat(BridgeInstants.isFuture(null, now)).isFalse();
    }

    @Test
    @DisplayName("미래 인증 시각은 도장에서 빠지고 무시한 값이 따로 남는다")
    void aFutureAuthenticationTimeLeavesTheStampAndIsKeptApart() {
        Instant future = Instant.now().plusSeconds(3_600);
        Map<String, Object> attributes = new LinkedHashMap<>(Map.of("authenticationTime", future, "department", "sales"));

        assertThat(BridgeInstants.authenticationTime(future, attributes)).isNull();

        assertThat(attributes).doesNotContainKey("authenticationTime")
                .containsEntry(BridgeInstants.IGNORED_FUTURE_AUTHENTICATION_TIME, future.toString())
                .containsEntry("department", "sales");
    }

    @Test
    @DisplayName("지난 인증 시각은 그대로 쓰고 속성을 바꾸지 않는다")
    void aPastAuthenticationTimeIsUsedAsItIs() {
        Map<String, Object> attributes = new LinkedHashMap<>(Map.of("authenticationTime", AT));

        assertThat(BridgeInstants.authenticationTime(AT, attributes)).isEqualTo(AT);
        assertThat(BridgeInstants.authenticationTime(null, attributes)).isNull();

        assertThat(attributes).containsOnlyKeys("authenticationTime");
    }
}
