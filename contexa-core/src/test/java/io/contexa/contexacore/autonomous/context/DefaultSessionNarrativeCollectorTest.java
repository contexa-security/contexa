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

import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import java.time.Instant;
import io.contexa.contexacore.autonomous.context.support.SessionStart;
import java.time.ZoneId;
import io.contexa.contexacore.autonomous.context.collector.DefaultSessionNarrativeCollector;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacore.autonomous.context.collector.SessionNarrativeSnapshot;

class DefaultSessionNarrativeCollectorTest {

    private static final String WINDOWS_CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            + "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
    private static final String MAC_SAFARI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
            + "(KHTML, like Gecko) Version/17.5 Safari/605.1.15";

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
                .timestamp(LocalDateTime.of(2026, 3, 25, 9, 0).atZone(ZoneId.systemDefault()).toInstant())
                .build();

        // 세션이 없는 요청은 회차 비교의 기준점이 될 수 없으므로 서사를 만들면 안 된다.
        assertThat(collect(event)).isEmpty();
    }

    @Test
    @DisplayName("같은 세션의 반복 요청에서는 이전 경로와 간격과 행동 순서가 정확히 연결되어야 한다")
    void collect_repeatedSessionRequests_buildsNarrativeSnapshot() {
        collect(event(
                "session-1",
                LocalDateTime.of(2026, 3, 25, 9, 0, 0),
                "/api/customer/list",
                "GET",
                true,
                "READ"));

        SessionNarrativeSnapshot snapshot = collect(event(
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
        collect(event(
                "session-rapid",
                LocalDateTime.of(2026, 3, 25, 9, 10, 0),
                "/api/customer/export",
                "POST",
                true,
                "EXPORT"));
        collect(event(
                "session-rapid",
                LocalDateTime.of(2026, 3, 25, 9, 10, 1),
                "/api/customer/export",
                "POST",
                true,
                "EXPORT"));

        SessionNarrativeSnapshot snapshot = collect(event(
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
        assertThat(collect(event)).isEmpty();
    }

    @Test
    @DisplayName("비보호 요청은 전체 행동 순서에는 남아도 protectable sequence에는 들어가면 안 된다")
    void collect_nonProtectableRequest_excludesProtectableSequence() {
        SessionNarrativeSnapshot snapshot = collect(event(
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
    @DisplayName("a protected method declared privileged makes a protectable request")
    void collect_countsAMethodDeclaredPrivilegedAsProtectable() {
        SecurityEvent grant = SecurityEvent.builder()
                .sessionId("session-grant")
                .timestamp(LocalDateTime.of(2026, 3, 25, 9, 20, 0).atZone(ZoneId.systemDefault()).toInstant())
                .description("POST /api/admin/role-grants")
                .build();
        grant.addMetadata("requestPath", "/api/admin/role-grants");
        grant.addMetadata("httpMethod", "POST");
        grant.addMetadata("actionFamily", "ADMIN");
        grant.addMetadata("protectablePrivileged", true);

        SessionNarrativeSnapshot snapshot = collect(grant).orElseThrow();

        // P3 gate: the method's declaration travels under its own key and still marks the request protectable.
        assertThat(snapshot.getSessionProtectableSequence()).containsExactly("/api/admin/role-grants");
    }

    @Test
    @DisplayName("회차 사이에 status나 evidence 요청이 끼어들어도 실제 보호 리소스 흐름은 유지되어야 한다")
    void collect_noiseBetweenRounds_shouldNotRewritePreviousPathOrActionSequence() {
        collect(event(
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
        assertThat(collect(noise)).isEmpty();

        SessionNarrativeSnapshot snapshot = collect(event(
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

    @Test
    @DisplayName("the session age counts from the sign-in and says so; the first analysed request is a new session")
    void collect_countsTheSessionFromTheSignIn() {
        SecurityEvent first = event("session-login", LocalDateTime.of(2026, 9, 30, 14, 1), "/api/customer/list", "GET",
                false, "READ");
        first.addMetadata("authenticationTime", signInAt().toString());
        SessionNarrativeSnapshot firstSnapshot = collect(first).orElseThrow();

        SecurityEvent later = event("session-login", LocalDateTime.of(2026, 9, 30, 14, 5), "/api/customer/view", "GET",
                false, "READ");
        later.addMetadata("authenticationTime", signInAt().toString());
        SessionNarrativeSnapshot laterSnapshot = collect(later).orElseThrow();

        assertThat(firstSnapshot.getSessionAgeMinutes()).isEqualTo(1);
        assertThat(firstSnapshot.getSessionAgeBasis()).isEqualTo(SessionStart.LOGIN);
        assertThat(firstSnapshot.getNewSession()).isTrue();
        assertThat(laterSnapshot.getSessionAgeMinutes()).isEqualTo(5);
        assertThat(laterSnapshot.getNewSession()).isFalse();
    }

    @Test
    @DisplayName("without a sign-in or creation time the session counts from its first analysed request")
    void collect_countsFromTheFirstAnalysedRequestWithoutAStart() {
        collect(event("session-first", LocalDateTime.of(2026, 9, 30, 14, 1), "/api/customer/list", "GET",
                false, "READ"));
        SessionNarrativeSnapshot snapshot = collect(event("session-first", LocalDateTime.of(2026, 9, 30, 14, 5),
                "/api/customer/view", "GET", false, "READ")).orElseThrow();

        assertThat(snapshot.getSessionAgeMinutes()).isEqualTo(4);
        assertThat(snapshot.getSessionAgeBasis()).isEqualTo(SessionStart.FIRST_ANALYSED_REQUEST);
    }

    @Test
    @DisplayName("the session's earlier decisions are counted and listed oldest first (W1-11)")
    void collect_countsTheSessionsEarlierDecisions() {
        Instant at = Instant.parse("2026-09-30T03:17:00Z");
        dataStore.addSessionDecision("session-decisions", new SessionDecisionRecord(at, "POST",
                "/api/projects/GB-500/exports", null, "EXPORT", "CHALLENGE").encode());
        dataStore.addSessionDecision("session-decisions", new SessionDecisionRecord(at.plusSeconds(60), "POST",
                "/api/projects/GB-500/exports", null, "EXPORT", "CHALLENGE").encode());
        dataStore.addSessionDecision("session-decisions", new SessionDecisionRecord(at.plusSeconds(120), "GET",
                "/api/customers/CUS-0001", null, "READ", SessionDecisionRecord.AUTHORIZATION_DENIED).encode());
        dataStore.addSessionDecision("session-decisions", "not a decision record");

        SessionNarrativeSnapshot snapshot = collect(event("session-decisions",
                LocalDateTime.of(2026, 9, 30, 12, 20), "/api/projects/GB-500/exports", "POST", true, "EXPORT"))
                .orElseThrow();

        assertThat(snapshot.getRecentChallengeCount()).isEqualTo(2);
        assertThat(snapshot.getRecentBlockCount()).isZero();
        assertThat(snapshot.getRecentEscalationCount()).isZero();
        assertThat(snapshot.getSessionDecisionHistory()).containsExactly(
                "2026-09-30T03:17:00Z | POST /api/projects/GB-500/exports | EXPORT | CHALLENGE",
                "2026-09-30T03:18:00Z | POST /api/projects/GB-500/exports | EXPORT | CHALLENGE",
                "2026-09-30T03:19:00Z | GET /api/customers/CUS-0001 | READ | AUTHORIZATION_DENIED");
    }

    @Test
    @DisplayName("the session's decisions are passed as records with their targets and item counts (W2-5)")
    void collect_passesTheSessionsDecisionsAsRecords() {
        Instant at = Instant.parse("2026-09-30T14:20:00Z");
        SessionDecisionRecord export = new SessionDecisionRecord(at, "POST", "/api/projects/GB-500/exports", null,
                "EXPORT", "ALLOW", "projectKey=GB-500", 480);
        dataStore.addSessionDecision("session-records", export.encode());

        SessionNarrativeSnapshot snapshot = collect(event("session-records",
                LocalDateTime.of(2026, 9, 30, 14, 21), "/api/projects/GB-500/exports", "POST", true, "EXPORT"))
                .orElseThrow();

        assertThat(snapshot.getSessionDecisions()).containsExactly(export);
    }

    @Test
    @DisplayName("every earlier decision is counted; the listed history is the most recent ten (W1-11)")
    void collect_countsEveryDecisionAndListsTheMostRecent() {
        Instant at = Instant.parse("2026-09-30T03:00:00Z");
        for (int minute = 0; minute < 12; minute++) {
            dataStore.addSessionDecision("session-many", new SessionDecisionRecord(at.plusSeconds(60L * minute), "GET",
                    "/api/customers", null, "READ", "BLOCK").encode());
        }

        SessionNarrativeSnapshot snapshot = collect(event("session-many",
                LocalDateTime.of(2026, 9, 30, 12, 20), "/api/customers", "GET", true, "READ")).orElseThrow();

        assertThat(snapshot.getRecentBlockCount()).isEqualTo(12);
        assertThat(snapshot.getSessionDecisionHistory()).hasSize(10);
        assertThat(snapshot.getSessionDecisionHistory().get(0)).startsWith("2026-09-30T03:02:00Z");
    }

    private static Instant signInAt() {
        return LocalDateTime.of(2026, 9, 30, 14, 0).atZone(ZoneId.systemDefault()).toInstant();
    }

    @Test
    @DisplayName("an event description is not an action: a request with no action source is UNKNOWN (W2-1)")
    void collect_withoutAnActionSource_recordsUnknownNotTheDescription() {
        SecurityEvent event = SecurityEvent.builder()
                .sessionId("session-description")
                .timestamp(LocalDateTime.of(2026, 3, 25, 9, 0).atZone(ZoneId.systemDefault()).toInstant())
                .description("LLM-challenged MFA success - learning")
                .build();
        event.addMetadata("requestPath", "/api/customer/list");
        event.addMetadata("isProtectable", true);

        SessionNarrativeSnapshot snapshot = collect(event).orElseThrow();

        assertThat(snapshot.getSessionActionSequence()).containsExactly("UNKNOWN");
    }

    @Test
    @DisplayName("families stored in the earlier vocabulary read as the family they name (W2-1)")
    void collect_readsStoredFamiliesInTheOneVocabulary() {
        dataStore.addSessionNarrativeActionFamily("session-old", "CREATE");

        SessionNarrativeSnapshot snapshot = collect(event(
                        "session-old",
                        LocalDateTime.of(2026, 3, 25, 9, 1, 0),
                        "/api/customer/list",
                        "GET",
                        true,
                        "READ"))
                .orElseThrow();

        assertThat(snapshot.getSessionActionSequence()).containsExactly("WRITE", "READ");
        assertThat(snapshot.getPreviousActionFamily()).isEqualTo("WRITE");
    }

    @Test
    @DisplayName("a change of device and of network is stated against the client the session first came from (W2-14)")
    void collect_statesTheChangesAgainstTheSessionsFirstClient() {
        SessionNarrativeSnapshot first = collect(clientEvent("session-client", 0, WINDOWS_CHROME, "10.40.12.7",
                "CORPORATE")).orElseThrow();
        SessionNarrativeSnapshot moved = collect(clientEvent("session-client", 1, MAC_SAFARI, "203.0.113.9",
                "EXTERNAL")).orElseThrow();
        SessionNarrativeSnapshot back = collect(clientEvent("session-client", 2, WINDOWS_CHROME, "10.40.12.40",
                "CORPORATE")).orElseThrow();

        assertThat(first.getSessionDeviceChange()).isNull();
        assertThat(first.getSessionNetworkChange()).isNull();
        assertThat(moved.getSessionDeviceChange()).isEqualTo("Chrome/140 on WINDOWS -> Safari/17 on MAC");
        assertThat(moved.getSessionNetworkChange()).isEqualTo("10.40.12.0/24 (CORPORATE) -> 203.0.113.0/24 (EXTERNAL)");
        // The comparison is with the first client, not the previous request: back on it, nothing changed.
        assertThat(back.getSessionDeviceChange()).isNull();
        assertThat(back.getSessionNetworkChange()).isNull();
    }

    @Test
    @DisplayName("the first client is recorded once a decision is known; a browser update is no change of device (W2-14)")
    void collect_recordsTheFirstClientOnCommitAndSetsTheBrowserVersionAside() {
        SecurityEvent first = clientEvent("session-commit", 0, WINDOWS_CHROME, "10.40.12.7", null);
        collector.collect(first);
        assertThat(dataStore.getSessionFirstClient("session-commit")).isNull();
        collector.recorder().commit(first, "CHALLENGE", false);
        assertThat(dataStore.getSessionFirstClient("session-commit")).isEqualTo("UA|WINDOWS|Chrome/140|10.40.12.0/24|");

        SessionNarrativeSnapshot updated = collect(clientEvent("session-commit", 1,
                WINDOWS_CHROME.replace("Chrome/140", "Chrome/141"), "10.40.12.7", null)).orElseThrow();

        assertThat(updated.getSessionDeviceChange()).isNull();
        assertThat(updated.getSessionNetworkChange()).isNull();
    }

    @Test
    @DisplayName("a client that names no browser is a change from a browser; a request without one is not compared (W2-14)")
    void collect_aScriptClientIsAChangeAndAMissingUserAgentIsNotCompared() {
        collect(clientEvent("session-script", 0, WINDOWS_CHROME, "10.40.12.7", null));

        SessionNarrativeSnapshot script = collect(clientEvent("session-script", 1, "python-requests/2.31", "10.40.12.7",
                null)).orElseThrow();
        SessionNarrativeSnapshot unnamed = collect(clientEvent("session-script", 2, null, "10.40.12.7", null)).orElseThrow();

        assertThat(script.getSessionDeviceChange())
                .isEqualTo("Chrome/140 on WINDOWS -> a client that names no browser or operating system");
        assertThat(unnamed.getSessionDeviceChange()).isNull();
        assertThat(unnamed.getSessionNetworkChange()).isNull();
    }

    @Test
    @DisplayName("the first client follows the session to the id it gets at a step-up (W2-14)")
    void collect_comparesWithTheFirstClientAfterTheSessionIdChanges() {
        collect(clientEvent("session-before-step-up", 0, WINDOWS_CHROME, "10.40.12.7", null));
        dataStore.moveSessionRecords("session-before-step-up", "session-after-step-up");

        SessionNarrativeSnapshot after = collect(clientEvent("session-after-step-up", 1, MAC_SAFARI, "10.40.12.7", null))
                .orElseThrow();

        assertThat(after.getSessionDeviceChange()).isEqualTo("Chrome/140 on WINDOWS -> Safari/17 on MAC");
    }

    @Test
    @DisplayName("requests of one session decided out of the order they were made are read in the order made (N-SES-1, G4-2)")
    void requestsDecidedOutOfOrderAreReadInTheOrderTheyWereMade() {
        SecurityEvent first = event("session-order", LocalDateTime.of(2026, 3, 25, 9, 0, 0),
                "/api/projects/A/documents", "GET", true, "READ");
        first.addMetadata("requestId", "request-a");
        SecurityEvent second = event("session-order", LocalDateTime.of(2026, 3, 25, 9, 0, 1),
                "/api/projects/B/exports", "POST", true, "EXPORT");
        second.addMetadata("requestId", "request-b");
        // Both are resolved before either is decided, and the later one is decided first.
        collector.collect(first);
        collector.collect(second);
        collector.recorder().commit(second, "CHALLENGE", true);
        collector.recorder().commit(first, "ALLOW", true);

        SecurityEvent next = event("session-order", LocalDateTime.of(2026, 3, 25, 9, 0, 11),
                "/api/customer/list", "GET", true, "READ");
        next.addMetadata("requestId", "request-c");
        SessionNarrativeSnapshot snapshot = collector.collect(next).orElseThrow();

        assertThat(snapshot.getSessionProtectableSequence())
                .containsExactly("/api/projects/A/documents", "/api/projects/B/exports", "/api/customer/list");
        assertThat(snapshot.getSessionActionSequence()).containsExactly("READ", "EXPORT", "READ");
        assertThat(snapshot.getPreviousPath()).isEqualTo("/api/projects/B/exports");
        assertThat(snapshot.getLastRequestIntervalMs()).isEqualTo(10_000L);
        assertThat(snapshot.getSessionDecisions()).extracting(SessionDecisionRecord::path)
                .containsExactly("/api/projects/A/documents", "/api/projects/B/exports");
    }

    private SecurityEvent clientEvent(String sessionId, int minute, String userAgent, String sourceIp, String zone) {
        SecurityEvent event = event(sessionId, LocalDateTime.of(2026, 3, 25, 9, minute), "/api/customer/list", "GET",
                true, "READ");
        event.setUserAgent(userAgent);
        event.setSourceIp(sourceIp);
        if (zone != null) {
            event.addMetadata("networkZone", zone);
        }
        return event;
    }

    private SecurityEvent event(String sessionId,
                                LocalDateTime timestamp,
                                String requestPath,
                                String httpMethod,
                                boolean protectable,
                                String actionFamily) {
        SecurityEvent event = SecurityEvent.builder()
                .sessionId(sessionId)
                .timestamp(timestamp.atZone(ZoneId.systemDefault()).toInstant())
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

    /** One request seen through to an enforced ALLOW, the way the pipeline records it (W2-7). */
    private Optional<SessionNarrativeSnapshot> collect(SecurityEvent event) {
        Optional<SessionNarrativeSnapshot> snapshot = collector.collect(event);
        collector.recorder().commit(event, "ALLOW", true);
        return snapshot;
    }
}
