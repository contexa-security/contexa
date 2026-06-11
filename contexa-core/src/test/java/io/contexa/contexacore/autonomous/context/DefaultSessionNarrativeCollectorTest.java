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
package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.context.collector.DefaultSessionNarrativeCollector;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacore.autonomous.context.collector.SessionNarrativeSnapshot;

class DefaultSessionNarrativeCollectorTest {

    private SecurityContextDataStore dataStore;
    private DefaultSessionNarrativeCollector collector;

    @BeforeEach
    void setUp() {
        dataStore = new InMemorySecurityContextDataStore();
        collector = new DefaultSessionNarrativeCollector(dataStore);
    }

    @Test
    @DisplayName("세션 ID가 없으면 세션 서사는 수집되지 않아야 한다")
    void collect_withoutSessionId_returnsEmpty() {
        SecurityEvent event = SecurityEvent.builder()
                .timestamp(LocalDateTime.of(2026, 3, 25, 9, 0))
                .build();

        // 세션이 없는 요청은 회차 비교의 기준점이 될 수 없으므로 서사를 만들면 안 된다.
        assertThat(collector.collect(event)).isEmpty();
    }

    @Test
    @DisplayName("같은 세션의 반복 요청에서는 이전 경로와 간격과 행동 순서가 정확히 연결되어야 한다")
    void collect_repeatedSessionRequests_buildsNarrativeSnapshot() {
        collector.collect(event(
                "session-1",
                LocalDateTime.of(2026, 3, 25, 9, 0, 0),
                "/api/customer/list",
                "GET",
                true,
                "READ"));

        SessionNarrativeSnapshot snapshot = collector.collect(event(
                        "session-1",
                        LocalDateTime.of(2026, 3, 25, 9, 0, 0, 800_000_000),
                        "/api/customer/export",
                        "POST",
                        true,
                        "EXPORT"))
                .orElseThrow();

        // 이전 경로/행동/간격은 후속 회차에서 "직전 행위가 무엇이었는가"를 판단하는 핵심 근거다.
        assertThat(snapshot.getPreviousPath()).isEqualTo("/api/customer/list");
        assertThat(snapshot.getPreviousActionFamily()).isEqualTo("READ");
        assertThat(snapshot.getLastRequestIntervalMs()).isEqualTo(800L);
        assertThat(snapshot.getSessionActionSequence()).containsExactly("READ", "EXPORT");
        assertThat(snapshot.getSessionProtectableSequence())
                .containsExactly("/api/customer/list", "/api/customer/export");
        assertThat(snapshot.getBurstPattern()).isFalse();
        assertThat(snapshot.getSummary()).contains("Previous path /api/customer/list");
    }

    @Test
    @DisplayName("짧은 시간에 보호 요청이 연속되면 burst 패턴으로 식별되어야 한다")
    void collect_threeRapidProtectableRequests_flagsBurstPattern() {
        collector.collect(event(
                "session-rapid",
                LocalDateTime.of(2026, 3, 25, 9, 10, 0),
                "/api/customer/export",
                "POST",
                true,
                "EXPORT"));
        collector.collect(event(
                "session-rapid",
                LocalDateTime.of(2026, 3, 25, 9, 10, 1),
                "/api/customer/export",
                "POST",
                true,
                "EXPORT"));

        SessionNarrativeSnapshot snapshot = collector.collect(event(
                        "session-rapid",
                        LocalDateTime.of(2026, 3, 25, 9, 10, 2, 200_000_000),
                        "/api/customer/export",
                        "POST",
                        true,
                        "EXPORT"))
                .orElseThrow();

        // burst 패턴은 계정탈취나 자동화 남용의 초기 신호가 될 수 있으므로 누락되면 안 된다.
        assertThat(snapshot.getSessionProtectableSequence()).hasSize(3);
        assertThat(snapshot.getBurstPattern()).isTrue();
    }

    @Test
    @DisplayName("증거 조회와 같은 보조 경로는 프롬프트 세션 히스토리를 오염시키면 안 된다")
    void collect_supportRoute_returnsEmpty() {
        SecurityEvent event = event(
                "session-support",
                LocalDateTime.of(2026, 3, 25, 9, 30, 0),
                "/admin/api/security-test/evidence/server-truth",
                "GET",
                false,
                "READ");

        // support/evidence 경로가 세션 서사에 들어가면 userPrompt의 previousPath와 action sequence가 왜곡된다.
        assertThat(collector.collect(event)).isEmpty();
    }

    @Test
    @DisplayName("비보호 요청은 전체 행동 순서에는 남아도 protectable sequence에는 들어가면 안 된다")
    void collect_nonProtectableRequest_excludesProtectableSequence() {
        SessionNarrativeSnapshot snapshot = collector.collect(event(
                        "session-plain",
                        LocalDateTime.of(2026, 3, 25, 9, 20, 0),
                        "/actuator/health",
                        "GET",
                        false,
                        "READ"))
                .orElseThrow();

        // protectable sequence는 LLM이 민감 리소스 흐름만 비교할 때 쓰이므로 건강검진용 요청과 분리되어야 한다.
        assertThat(snapshot.getSessionActionSequence()).containsExactly("READ");
        assertThat(snapshot.getSessionProtectableSequence()).isEmpty();
        assertThat(snapshot.getBurstPattern()).isFalse();
    }

    @Test
    @DisplayName("회차 사이에 status나 evidence 요청이 끼어들어도 실제 보호 리소스 흐름은 유지되어야 한다")
    void collect_noiseBetweenRounds_shouldNotRewritePreviousPathOrActionSequence() {
        collector.collect(event(
                "session-round",
                LocalDateTime.of(2026, 3, 25, 10, 0, 0),
                "/admin/api/security-test/sensitive/resource-001",
                "GET",
                true,
                "READ"));

        SecurityEvent noise = event(
                "session-round",
                LocalDateTime.of(2026, 3, 25, 10, 0, 5),
                "/admin/api/security-test/evidence/server-truth",
                "GET",
                false,
                "READ");
        assertThat(collector.collect(noise)).isEmpty();

        SessionNarrativeSnapshot snapshot = collector.collect(event(
                        "session-round",
                        LocalDateTime.of(2026, 3, 25, 10, 0, 30),
                        "/admin/api/security-test/sensitive/resource-001",
                        "GET",
                        true,
                        "READ"))
                .orElseThrow();

        // 브라우저 테스트 중간의 status/evidence 호출이 previousPath를 덮어쓰면
        // 후속 회차 프롬프트가 "직전 보호 요청" 대신 UI 보조 요청을 비교 대상으로 삼게 된다.
        assertThat(snapshot.getPreviousPath()).isEqualTo("/admin/api/security-test/sensitive/resource-001");
        assertThat(snapshot.getPreviousActionFamily()).isEqualTo("READ");
        assertThat(snapshot.getSessionProtectableSequence())
                .containsExactly(
                        "/admin/api/security-test/sensitive/resource-001",
                        "/admin/api/security-test/sensitive/resource-001");
        assertThat(snapshot.getSessionActionSequence()).containsExactly("READ", "READ");
    }

    private SecurityEvent event(String sessionId,
                                LocalDateTime timestamp,
                                String requestPath,
                                String httpMethod,
                                boolean protectable,
                                String actionFamily) {
        SecurityEvent event = SecurityEvent.builder()
                .sessionId(sessionId)
                .timestamp(timestamp)
                .description(httpMethod + " " + requestPath)
                .build();
        event.addMetadata("requestPath", requestPath);
        event.addMetadata("httpMethod", httpMethod);
        event.addMetadata("actionFamily", actionFamily);
        event.addMetadata("isProtectable", protectable);
        if (protectable) {
            event.addMetadata("className", "io.contexa.CustomerExportController");
            event.addMetadata("methodName", "handle");
            event.addMetadata("granted", true);
        }
        return event;
    }
}
