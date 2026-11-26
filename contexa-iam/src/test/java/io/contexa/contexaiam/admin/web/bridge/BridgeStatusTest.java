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
package io.contexa.contexaiam.admin.web.bridge;

import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.identity.IdentityDiagnostics;
import io.contexa.contexacommon.security.bridge.subject.ContexaAuthentication;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.subject.SubjectProblem;
import io.contexa.contexaiam.admin.web.bridge.BridgeStatus.Effect;
import io.contexa.contexaiam.admin.web.bridge.BridgeStatus.Problem;
import io.contexa.contexaiam.admin.web.bridge.BridgeStatus.Share;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

@DisplayName("사용자 연동 상태 화면 값")
class BridgeStatusTest {

    @Test
    @DisplayName("진단 값이 없으면 꺼진 화면이고 목록은 모두 비어 있다")
    void withoutTheDiagnosticsTheScreenIsOff() {
        BridgeStatus status = BridgeStatus.of(null);

        assertThat(status).isEqualTo(BridgeStatus.off());
        assertThat(status.available()).isFalse();
        assertThat(status.counted()).isFalse();
        assertThat(status.attention()).isFalse();
        assertThat(status.outcomes()).isEmpty();
        assertThat(status.sources()).isEmpty();
        assertThat(status.problems()).isEmpty();
        assertThat(status.quietProblems()).isEmpty();
        assertThat(status.emailBreakdown()).isEmpty();
    }

    @Test
    @DisplayName("결과 네 가지는 정해진 순서로 건수와 전체 대비 비율을 가진다")
    void theFourOutcomesHaveTheirCountsAndShares() {
        BridgeStatus status = BridgeStatus.of(snapshot(
                outcomes(80, 15, 4, 1), sources(50, 20, 5, 5), problems(Map.of())));

        assertThat(status.available()).isTrue();
        assertThat(status.checks()).isEqualTo(100);
        assertThat(status.resolved()).isEqualTo(80);
        assertThat(status.outcomes()).extracting(Share::code)
                .containsExactly("RESOLVED", "ABSENT", "INVALID", "FAILED");
        assertThat(status.outcomes()).extracting(Share::count).containsExactly(80L, 15L, 4L, 1L);
        assertThat(status.outcomes().get(0).share()).isCloseTo(0.80, within(1e-9));
        assertThat(status.outcomes().get(3).share()).isCloseTo(0.01, within(1e-9));
        assertThat(status.outcomes().stream().mapToDouble(Share::share).sum()).isCloseTo(1.0, within(1e-9));
    }

    @Test
    @DisplayName("규칙 위반이나 실패가 한 건이라도 있으면 눈에 띄게 표시한다")
    void aRuleBreakOrAFailureIsMarked() {
        BridgeStatus status = BridgeStatus.of(snapshot(outcomes(10, 0, 2, 3), sources(10, 0, 0, 0), problems(Map.of())));

        assertThat(status.attention()).isTrue();
        assertThat(status.invalid()).isEqualTo(2);
        assertThat(status.failed()).isEqualTo(3);
        assertThat(status.outcomes()).filteredOn(Share::alert).extracting(Share::code)
                .containsExactly("INVALID", "FAILED");
    }

    @Test
    @DisplayName("규칙 위반과 실패가 0건이면 표시하지 않는다")
    void noRuleBreakAndNoFailureIsNotMarked() {
        BridgeStatus status = BridgeStatus.of(snapshot(outcomes(10, 5, 0, 0), sources(10, 0, 0, 0), problems(Map.of())));

        assertThat(status.attention()).isFalse();
        assertThat(status.outcomes()).noneMatch(Share::alert);
    }

    @Test
    @DisplayName("확인 경로 비율은 성립한 건수를 전체로 계산한다")
    void theSourcesShareTheResolved() {
        BridgeStatus status = BridgeStatus.of(snapshot(outcomes(40, 60, 0, 0), sources(10, 30, 0, 0), problems(Map.of())));

        assertThat(status.sources()).extracting(Share::code)
                .containsExactly("SPRING_SECURITY", "RESOLVER", "REQUEST_ATTRIBUTE", "CONTEXA_ACCOUNT");
        assertThat(status.sources().get(0).share()).isCloseTo(0.25, within(1e-9));
        assertThat(status.sources().get(1).share()).isCloseTo(0.75, within(1e-9));
        assertThat(status.sources()).noneMatch(Share::alert);
    }

    @Test
    @DisplayName("확인한 요청이 없으면 비율은 모두 0이고 셈이 없는 상태다")
    void withoutAnyResolutionEveryShareIsZero() {
        BridgeStatus status = BridgeStatus.of(snapshot(outcomes(0, 0, 0, 0), sources(0, 0, 0, 0), problems(Map.of())));

        assertThat(status.available()).isTrue();
        assertThat(status.counted()).isFalse();
        assertThat(status.outcomes()).allSatisfy(share -> assertThat(share.share()).isZero());
        assertThat(status.sources()).allSatisfy(share -> assertThat(share.share()).isZero());
        assertThat(status.problems()).isEmpty();
        assertThat(status.quietProblems()).hasSize(SubjectProblem.values().length);
    }

    @Test
    @DisplayName("메일 주소 문제 건수는 메일 문제 세 가지의 합이고 내역은 세 가지를 순서대로 보인다")
    void theMailAddressProblemsAreTheSumOfTheThree() {
        BridgeStatus status = BridgeStatus.of(snapshot(outcomes(30, 0, 0, 0), sources(30, 0, 0, 0), problems(Map.of(
                SubjectProblem.EMAIL_MISSING, 7L, SubjectProblem.EMAIL_TOO_LONG, 2L,
                SubjectProblem.EMAIL_PROVIDER_FAILED, 5L, SubjectProblem.DISPLAY_NAME_DROPPED, 9L))));

        assertThat(status.emailProblems()).isEqualTo(9);
        assertThat(status.emailBreakdown()).extracting(Problem::kind).containsExactly(
                SubjectProblem.EMAIL_MISSING, SubjectProblem.EMAIL_MALFORMED, SubjectProblem.EMAIL_TOO_LONG);
        assertThat(status.emailBreakdown()).extracting(Problem::count).containsExactly(7L, 0L, 2L);
    }

    @Test
    @DisplayName("발생한 문제는 많은 순으로, 발생하지 않은 문제는 정의 순서로 나뉘고 합치면 모든 문제다")
    void theProblemsMetComeFirstByCountAndTheRestInTheirOrder() {
        BridgeStatus status = BridgeStatus.of(snapshot(outcomes(5, 0, 1, 0), sources(5, 0, 0, 0), problems(Map.of(
                SubjectProblem.RESOLVER_SLOW, 3L, SubjectProblem.USER_ID_BLANK, 3L, SubjectProblem.EMAIL_MISSING, 8L))));

        assertThat(status.problems()).extracting(Problem::kind).containsExactly(
                SubjectProblem.EMAIL_MISSING, SubjectProblem.USER_ID_BLANK, SubjectProblem.RESOLVER_SLOW);
        assertThat(status.quietProblems()).extracting(Problem::kind).isSortedAccordingTo(
                (left, right) -> Integer.compare(left.ordinal(), right.ordinal()));
        assertThat(Stream.concat(status.problems().stream(), status.quietProblems().stream()).map(Problem::kind))
                .containsExactlyInAnyOrder(SubjectProblem.values());
        assertThat(status.quietProblems()).allSatisfy(problem -> assertThat(problem.count()).isZero());
    }

    @Test
    @DisplayName("문제의 영향은 아이디 규칙 위반과 메일 문제 분류와 어긋나지 않는다")
    void theEffectOfAProblemAgreesWithItsKind() {
        for (SubjectProblem problem : SubjectProblem.values()) {
            Effect effect = Effect.of(problem);
            if (problem.breaksTheUserId()) {
                assertThat(effect).as(problem.name()).isEqualTo(Effect.USER_NOT_RESOLVED);
            }
            if (problem.breaksTheEmail()) {
                assertThat(effect).as(problem.name()).isEqualTo(Effect.NO_EMAIL);
            }
        }
        assertThat(Effect.of(SubjectProblem.RESOLVER_FAILED)).isEqualTo(Effect.USER_NOT_RESOLVED);
        assertThat(Effect.of(SubjectProblem.MAPPER_FAILED)).isEqualTo(Effect.USER_NOT_RESOLVED);
        assertThat(Effect.of(SubjectProblem.UNSUPPORTED_PRINCIPAL)).isEqualTo(Effect.USER_NOT_RESOLVED);
        assertThat(Effect.of(SubjectProblem.NOT_A_SUBJECT)).isEqualTo(Effect.USER_NOT_RESOLVED);
        assertThat(Effect.of(SubjectProblem.AUTHORITIES_TRIMMED)).isEqualTo(Effect.VALUE_LEFT_OUT);
        assertThat(Effect.of(SubjectProblem.SOURCES_DISAGREE)).isEqualTo(Effect.NOTICE);
    }

    @Test
    @DisplayName("문제 문구에 넣는 제한 값은 코드가 지키는 상수에서 온다")
    void theLimitsInTheWordsComeFromTheConstants() {
        assertThat(new Problem(SubjectProblem.USER_ID_TOO_LONG, 1).args()).containsExactly(ContexaSubject.MAX_TEXT_LENGTH);
        assertThat(new Problem(SubjectProblem.DISPLAY_NAME_DROPPED, 1).args())
                .containsExactly(ContexaSubject.MAX_DISPLAY_NAME_LENGTH);
        assertThat(new Problem(SubjectProblem.AUTHORITIES_TRIMMED, 1).args())
                .containsExactly(ContexaSubject.MAX_AUTHORITIES, ContexaSubject.MAX_TEXT_LENGTH);
        assertThat(new Problem(SubjectProblem.AUTHENTICATION_FIELD_DROPPED, 1).args())
                .containsExactly(ContexaAuthentication.MAX_LENGTH);
        assertThat(new Problem(SubjectProblem.NOT_A_SUBJECT, 1).args()).containsExactly(ContexaSubject.REQUEST_ATTRIBUTE);
        assertThat(new Problem(SubjectProblem.EMAIL_MISSING, 1).args()).isEmpty();
        assertThat(new Share(BridgeStatus.SOURCE, "REQUEST_ATTRIBUTE", 1, 1.0, false).args())
                .containsExactly(ContexaSubject.REQUEST_ATTRIBUTE);
        assertThat(new Share(BridgeStatus.OUTCOME, "RESOLVED", 1, 1.0, false).args()).isEmpty();
    }

    @Test
    @DisplayName("화면 문구 키는 한 규칙으로 만들어진다")
    void theKeysOfTheWordsFollowOneRule() {
        Problem problem = new Problem(SubjectProblem.EMAIL_MISSING, 1);
        Share outcome = new Share(BridgeStatus.OUTCOME, "INVALID", 1, 1.0, true);

        assertThat(problem.nameKey()).isEqualTo("admin.bridge.status.problem.EMAIL_MISSING.name");
        assertThat(problem.meaningKey()).isEqualTo("admin.bridge.status.problem.EMAIL_MISSING.meaning");
        assertThat(problem.actionKey()).isEqualTo("admin.bridge.status.problem.EMAIL_MISSING.action");
        assertThat(problem.effect().key()).isEqualTo("admin.bridge.status.effect.NO_EMAIL");
        assertThat(outcome.nameKey()).isEqualTo("admin.bridge.status.outcome.INVALID.name");
        assertThat(outcome.descriptionKey()).isEqualTo("admin.bridge.status.outcome.INVALID.desc");
    }

    @Test
    @DisplayName("실제 진단 계수기의 값을 그대로 옮긴다")
    void theCountsOfTheDiagnosticsAreTakenAsTheyAre() {
        IdentityDiagnostics diagnostics = new IdentityDiagnostics();
        ContexaSubject withoutMail = ContexaSubject.of("alice", null).build();
        diagnostics.record(ContexaIdentity.resolved(withoutMail, ContexaIdentity.Source.RESOLVER,
                withoutMail.getProblems(), null));
        diagnostics.problem(SubjectProblem.EMAIL_MISSING, "named by resolver");
        diagnostics.record(ContexaIdentity.unresolved(ContexaIdentity.Outcome.INVALID, List.of(SubjectProblem.USER_ID_BLANK)));
        diagnostics.problem(SubjectProblem.USER_ID_BLANK, "named by resolver");
        diagnostics.record(ContexaIdentity.absent());

        BridgeStatus status = BridgeStatus.of(diagnostics.snapshot());

        assertThat(status.checks()).isEqualTo(3);
        assertThat(status.resolved()).isEqualTo(1);
        assertThat(status.outcomes()).extracting(Share::count).containsExactly(1L, 1L, 1L, 0L);
        assertThat(status.sources()).extracting(Share::count).containsExactly(0L, 1L, 0L, 0L);
        assertThat(status.emailProblems()).isEqualTo(1);
        assertThat(status.problems()).extracting(Problem::kind)
                .containsExactly(SubjectProblem.USER_ID_BLANK, SubjectProblem.EMAIL_MISSING);
        assertThat(status.attention()).isTrue();
    }

    private static IdentityDiagnostics.Snapshot snapshot(Map<ContexaIdentity.Outcome, Long> outcomes,
                                                         Map<ContexaIdentity.Source, Long> sources,
                                                         Map<SubjectProblem, Long> problems) {
        return new IdentityDiagnostics.Snapshot(outcomes, sources, problems);
    }

    private static Map<ContexaIdentity.Outcome, Long> outcomes(long resolved, long absent, long invalid, long failed) {
        Map<ContexaIdentity.Outcome, Long> counts = new EnumMap<>(ContexaIdentity.Outcome.class);
        counts.put(ContexaIdentity.Outcome.RESOLVED, resolved);
        counts.put(ContexaIdentity.Outcome.ABSENT, absent);
        counts.put(ContexaIdentity.Outcome.INVALID, invalid);
        counts.put(ContexaIdentity.Outcome.FAILED, failed);
        return counts;
    }

    private static Map<ContexaIdentity.Source, Long> sources(long springSecurity, long resolver, long requestAttribute,
                                                             long contexaAccount) {
        Map<ContexaIdentity.Source, Long> counts = new EnumMap<>(ContexaIdentity.Source.class);
        counts.put(ContexaIdentity.Source.SPRING_SECURITY, springSecurity);
        counts.put(ContexaIdentity.Source.RESOLVER, resolver);
        counts.put(ContexaIdentity.Source.REQUEST_ATTRIBUTE, requestAttribute);
        counts.put(ContexaIdentity.Source.CONTEXA_ACCOUNT, contexaAccount);
        return counts;
    }

    private static Map<SubjectProblem, Long> problems(Map<SubjectProblem, Long> met) {
        Map<SubjectProblem, Long> counts = new EnumMap<>(SubjectProblem.class);
        Arrays.stream(SubjectProblem.values()).forEach(problem -> counts.put(problem, met.getOrDefault(problem, 0L)));
        return counts;
    }
}
