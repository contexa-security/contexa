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
package io.contexa.contexacommon.security.bridge.subject;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The rules of the value an application hands Contexa (the legacy integration standard v2, section 3). */
@DisplayName("레거시 연동 표준 v2: ContexaSubject 규칙")
class ContexaSubjectTest {

    @Test
    @DisplayName("아이디와 메일이 맞으면 신원과 메일이 그대로 성립하고 문제가 없다")
    void aUserWithIdAndMail() {
        ContexaSubject subject = ContexaSubject.of("  Kim01 ", " kim01@seum.example ").displayName("김철수").build();

        assertThat(subject.hasUserId()).isTrue();
        assertThat(subject.getUserId()).isEqualTo("Kim01");
        assertThat(subject.hasEmail()).isTrue();
        assertThat(subject.getEmail()).isEqualTo("kim01@seum.example");
        assertThat(subject.getDisplayName()).isEqualTo("김철수");
        assertThat(subject.getProblems()).isEmpty();
    }

    @Test
    @DisplayName("아이디가 없거나 공백이면 신원이 성립하지 않는다(예외는 던지지 않는다)")
    void aBlankUserIdIsNoIdentity() {
        assertThatCode(() -> ContexaSubject.of(null, null).build()).doesNotThrowAnyException();
        ContexaSubject subject = ContexaSubject.of("   ", "kim01@seum.example").build();

        assertThat(subject.hasUserId()).isFalse();
        assertThat(subject.getUserId()).isNull();
        assertThat(subject.getProblems()).containsExactly(SubjectProblem.USER_ID_BLANK);
    }

    @Test
    @DisplayName("아이디가 255자를 넘으면 신원이 성립하지 않는다")
    void aTooLongUserIdIsNoIdentity() {
        ContexaSubject subject = ContexaSubject.of("a".repeat(256), "kim01@seum.example").build();

        assertThat(subject.hasUserId()).isFalse();
        assertThat(subject.getProblems()).containsExactly(SubjectProblem.USER_ID_TOO_LONG);
        assertThat(ContexaSubject.of("a".repeat(255), "kim01@seum.example").build().hasUserId()).isTrue();
    }

    @Test
    @DisplayName("아이디에 제어 문자가 있으면 신원이 성립하지 않는다(로그·프롬프트 주입 방지)")
    void aUserIdWithAControlCharacterIsNoIdentity() {
        ContexaSubject subject = ContexaSubject.of("kim01\nadmin", "kim01@seum.example").build();

        assertThat(subject.hasUserId()).isFalse();
        assertThat(subject.getProblems()).containsExactly(SubjectProblem.USER_ID_CONTROL_CHARACTER);
        assertThat(ContexaSubject.of("kim01\u0000", "kim01@seum.example").build().getProblems())
                .containsExactly(SubjectProblem.USER_ID_CONTROL_CHARACTER);
        assertThat(ContexaSubject.of("kim01\n", "kim01@seum.example").build().getUserId()).isEqualTo("kim01");
    }

    @Test
    @DisplayName("아이디의 대소문자는 바꾸지 않는다")
    void theCaseOfTheUserIdIsKept() {
        assertThat(ContexaSubject.of("PLAIN-K9", "k9@seum.example").build().getUserId()).isEqualTo("PLAIN-K9");
    }

    @Test
    @DisplayName("메일이 없으면 신원은 성립하고 메일 결손만 표시된다")
    void aMissingMailKeepsTheIdentity() {
        ContexaSubject subject = ContexaSubject.of("kim01", null).build();

        assertThat(subject.hasUserId()).isTrue();
        assertThat(subject.hasEmail()).isFalse();
        assertThat(subject.getProblems()).containsExactly(SubjectProblem.EMAIL_MISSING);
    }

    @ParameterizedTest
    @ValueSource(strings = {"kim01", "kim01@", "@seum.example", "kim@01@seum.example", "kim 01@seum.example",
            "kim01@.seum.example", "kim01@seum.example.", "kim01@seum..example"})
    @DisplayName("주소 형식이 아닌 메일은 버리고 신원은 유지한다")
    void aMalformedMailKeepsTheIdentity(String address) {
        ContexaSubject subject = ContexaSubject.of("kim01", address).build();

        assertThat(subject.hasUserId()).isTrue();
        assertThat(subject.getEmail()).isNull();
        assertThat(subject.getProblems()).containsExactly(SubjectProblem.EMAIL_MALFORMED);
    }

    @Test
    @DisplayName("점이 없는 사내 메일 도메인도 주소로 받는다")
    void aLocalMailDomainIsAnAddress() {
        assertThat(ContexaSubject.of("kim01", "kim01@mailhost").build().getEmail()).isEqualTo("kim01@mailhost");
    }

    @Test
    @DisplayName("255자를 넘는 메일은 결손으로 본다")
    void aTooLongMailIsMissing() {
        ContexaSubject subject = ContexaSubject.of("kim01", "a".repeat(250) + "@seum.example").build();

        assertThat(subject.getEmail()).isNull();
        assertThat(subject.getProblems()).containsExactly(SubjectProblem.EMAIL_TOO_LONG);
    }

    @Test
    @DisplayName("규칙을 어긴 선택 값은 그 값만 버리고 문제로 알린다")
    void anOptionalValueThatBreaksItsRuleIsLeftOut() {
        ContexaSubject subject = ContexaSubject.of("kim01", "kim01@seum.example")
                .displayName("x".repeat(101))
                .organizationId("org\u0007")
                .tenantId("t".repeat(256))
                .sessionKey("line\r\nbreak")
                .build();

        assertThat(subject.hasUserId()).isTrue();
        assertThat(subject.getDisplayName()).isNull();
        assertThat(subject.getOrganizationId()).isNull();
        assertThat(subject.getTenantId()).isNull();
        assertThat(subject.getSessionKey()).isNull();
        assertThat(subject.getProblems()).containsExactlyInAnyOrder(SubjectProblem.DISPLAY_NAME_DROPPED,
                SubjectProblem.ORGANIZATION_DROPPED, SubjectProblem.TENANT_DROPPED, SubjectProblem.SESSION_KEY_DROPPED);
    }

    @Test
    @DisplayName("권한은 순서대로 두고, 빈 값은 건너뛰며, 상한을 넘거나 규칙을 어긴 것만 버린다")
    void authoritiesAreKeptInOrderWithinTheLimit() {
        List<String> many = new ArrayList<>(Arrays.asList("ROLE_USER", null, " ", "MENU_HR", "ROLE_USER"));
        for (int index = 0; index < ContexaSubject.MAX_AUTHORITIES + 5; index++) {
            many.add("P" + index);
        }
        ContexaSubject subject = ContexaSubject.of("kim01", "kim01@seum.example").authorities(many).build();

        assertThat(subject.getAuthorities()).hasSize(ContexaSubject.MAX_AUTHORITIES);
        assertThat(subject.getAuthorities()).startsWith("ROLE_USER", "MENU_HR", "P0");
        assertThat(subject.getProblems()).containsExactly(SubjectProblem.AUTHORITIES_TRIMMED);
        assertThatThrownBy(() -> subject.getAuthorities().add("ROLE_ADMIN"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("로그인 방식 값은 바뀌지 않는 값이고, 너무 긴 방식은 버린다")
    void theSignInFactsAreImmutableAndBounded() {
        Instant loginAt = Instant.parse("2026-11-26T01:00:00Z");
        ContexaAuthentication facts = ContexaAuthentication.of("PASSWORD+OTP");
        ContexaAuthentication verified = facts.mfa(true).authenticatedAt(loginAt).assurance("AAL2");

        assertThat(facts.getMfa()).isNull();
        assertThat(verified.getMethod()).isEqualTo("PASSWORD+OTP");
        assertThat(verified.getMfa()).isTrue();
        assertThat(verified.getAuthenticatedAt()).isEqualTo(loginAt);

        ContexaSubject subject = ContexaSubject.of("kim01", "kim01@seum.example")
                .authentication(ContexaAuthentication.of("M".repeat(65)).mfa(false))
                .build();
        assertThat(subject.getAuthentication().getMethod()).isNull();
        assertThat(subject.getAuthentication().getMfa()).isFalse();
        assertThat(subject.getProblems()).containsExactly(SubjectProblem.AUTHENTICATION_FIELD_DROPPED);
    }

    @Test
    @DisplayName("에이전트를 이름 짓지 않은 위임은 버린다")
    void aDelegationWithoutAnAgentIsLeftOut() {
        ContexaSubject withAgent = ContexaSubject.of("kim01", "kim01@seum.example")
                .delegation(ContexaDelegation.of("report-agent").approvalRequired(true).build())
                .build();
        ContexaSubject withoutAgent = ContexaSubject.of("kim01", "kim01@seum.example")
                .delegation(ContexaDelegation.of(" ").build())
                .build();

        assertThat(withAgent.getDelegation().getAgentId()).isEqualTo("report-agent");
        assertThat(withAgent.getDelegation().getApprovalRequired()).isTrue();
        assertThat(withoutAgent.getDelegation()).isNull();
        assertThat(withoutAgent.getProblems()).containsExactly(SubjectProblem.DELEGATION_DROPPED);
    }

    @Test
    @DisplayName("메일만 바꾼 사본은 같은 규칙으로 메일을 검사하고, 다른 값의 문제 기록은 그대로 둔다")
    void anotherMailAddressKeepsTheOtherProblems() {
        ContexaSubject withoutMail = ContexaSubject.of("kim01", null).displayName("x".repeat(101)).build();

        ContexaSubject withMail = withoutMail.withEmail("kim01@seum.example");
        ContexaSubject withBadMail = withoutMail.withEmail("kim01");

        assertThat(withMail.getEmail()).isEqualTo("kim01@seum.example");
        assertThat(withMail.getUserId()).isEqualTo("kim01");
        assertThat(withMail.getProblems()).containsExactly(SubjectProblem.DISPLAY_NAME_DROPPED);
        assertThat(withBadMail.getEmail()).isNull();
        assertThat(withBadMail.getProblems()).containsExactlyInAnyOrder(SubjectProblem.DISPLAY_NAME_DROPPED,
                SubjectProblem.EMAIL_MALFORMED);
    }

    @Test
    @DisplayName("문자열 표현에는 메일 주소를 쓰지 않는다")
    void theTextOfASubjectKeepsTheMailAddressOut() {
        assertThat(ContexaSubject.of("kim01", "kim01@seum.example").build().toString())
                .contains("kim01")
                .doesNotContain("seum.example");
    }

    @Test
    @DisplayName("레거시가 넣는 요청 속성 이름은 Contexa 출력 이름(ctxa.bridge.*)과 겹치지 않는다")
    void theRequestAttributeIsApartFromContexasOutput() {
        assertThat(ContexaSubject.REQUEST_ATTRIBUTE).isEqualTo("ctxa.subject").doesNotStartWith("ctxa.bridge.");
    }
}
