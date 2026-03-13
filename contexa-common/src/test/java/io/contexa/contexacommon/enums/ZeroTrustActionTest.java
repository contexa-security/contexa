package io.contexa.contexacommon.enums;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class ZeroTrustActionTest {

    @Nested
    @DisplayName("fromString parsing")
    class FromStringTest {

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"   ", "\t"})
        @DisplayName("Should return ESCALATE for null, empty, or blank input")
        void shouldReturnEscalateForNullOrBlank(String input) {
            assertThat(ZeroTrustAction.fromString(input)).isEqualTo(ZeroTrustAction.ESCALATE);
        }

        @ParameterizedTest
        @CsvSource({
                "ALLOW, ALLOW",
                "BLOCK, BLOCK",
                "CHALLENGE, CHALLENGE",
                "ESCALATE, ESCALATE",
                "PENDING_ANALYSIS, PENDING_ANALYSIS"
        })
        @DisplayName("Should parse full action names correctly")
        void shouldParseFullNames(String input, ZeroTrustAction expected) {
            assertThat(ZeroTrustAction.fromString(input)).isEqualTo(expected);
        }

        @ParameterizedTest
        @CsvSource({
                "A, ALLOW",
                "B, BLOCK",
                "C, CHALLENGE",
                "E, ESCALATE"
        })
        @DisplayName("Should parse abbreviated action names correctly")
        void shouldParseAbbreviations(String input, ZeroTrustAction expected) {
            assertThat(ZeroTrustAction.fromString(input)).isEqualTo(expected);
        }

        @ParameterizedTest
        @ValueSource(strings = {"allow", "Allow", "aLlOw", "  ALLOW  "})
        @DisplayName("Should parse case-insensitively and trim whitespace")
        void shouldParseCaseInsensitively(String input) {
            assertThat(ZeroTrustAction.fromString(input)).isEqualTo(ZeroTrustAction.ALLOW);
        }

        @ParameterizedTest
        @ValueSource(strings = {"UNKNOWN", "X", "DENY", "123"})
        @DisplayName("Should return ESCALATE for unrecognized input")
        void shouldReturnEscalateForUnrecognizedInput(String input) {
            assertThat(ZeroTrustAction.fromString(input)).isEqualTo(ZeroTrustAction.ESCALATE);
        }
    }

    @Nested
    @DisplayName("httpStatus mapping")
    class HttpStatusTest {

        @ParameterizedTest
        @CsvSource({
                "ALLOW, 200",
                "CHALLENGE, 401",
                "BLOCK, 403",
                "ESCALATE, 423",
                "PENDING_ANALYSIS, 503"
        })
        @DisplayName("Should return correct HTTP status code for each action")
        void shouldReturnCorrectHttpStatus(ZeroTrustAction action, int expectedStatus) {
            assertThat(action.getHttpStatus()).isEqualTo(expectedStatus);
        }
    }

    @Nested
    @DisplayName("getDefaultTtl")
    class DefaultTtlTest {

        @Test
        @DisplayName("Should return null when ttlSeconds is negative (BLOCK)")
        void shouldReturnNullForNegativeTtl() {
            assertThat(ZeroTrustAction.BLOCK.getDefaultTtl()).isNull();
        }

        @Test
        @DisplayName("Should return null when ttlSeconds is zero (PENDING_ANALYSIS)")
        void shouldReturnNullForZeroTtl() {
            assertThat(ZeroTrustAction.PENDING_ANALYSIS.getDefaultTtl()).isNull();
        }

        @Test
        @DisplayName("Should return Duration for ALLOW with 1500 seconds")
        void shouldReturnDurationForAllow() {
            assertThat(ZeroTrustAction.ALLOW.getDefaultTtl()).isEqualTo(Duration.ofSeconds(1500));
        }

        @Test
        @DisplayName("Should return Duration for CHALLENGE with 1800 seconds")
        void shouldReturnDurationForChallenge() {
            assertThat(ZeroTrustAction.CHALLENGE.getDefaultTtl()).isEqualTo(Duration.ofSeconds(1800));
        }

        @Test
        @DisplayName("Should return Duration for ESCALATE with 300 seconds")
        void shouldReturnDurationForEscalate() {
            assertThat(ZeroTrustAction.ESCALATE.getDefaultTtl()).isEqualTo(Duration.ofSeconds(300));
        }
    }

    @Nested
    @DisplayName("isBlocking")
    class IsBlockingTest {

        @ParameterizedTest
        @CsvSource({
                "ALLOW, false",
                "BLOCK, true",
                "CHALLENGE, false",
                "ESCALATE, true",
                "PENDING_ANALYSIS, false"
        })
        @DisplayName("Should return true only for BLOCK and ESCALATE")
        void shouldIdentifyBlockingActions(ZeroTrustAction action, boolean expected) {
            assertThat(action.isBlocking()).isEqualTo(expected);
        }
    }

    @Nested
    @DisplayName("isAccessRestricted")
    class IsAccessRestrictedTest {

        @ParameterizedTest
        @CsvSource({
                "ALLOW, false",
                "BLOCK, true",
                "CHALLENGE, true",
                "ESCALATE, true",
                "PENDING_ANALYSIS, false"
        })
        @DisplayName("Should return true for BLOCK, CHALLENGE, and ESCALATE")
        void shouldIdentifyAccessRestrictedActions(ZeroTrustAction action, boolean expected) {
            assertThat(action.isAccessRestricted()).isEqualTo(expected);
        }
    }

    @Nested
    @DisplayName("getGrantedAuthority")
    class GrantedAuthorityTest {

        @Test
        @DisplayName("Should return null for ALLOW")
        void shouldReturnNullForAllow() {
            assertThat(ZeroTrustAction.ALLOW.getGrantedAuthority()).isNull();
        }

        @Test
        @DisplayName("Should return ROLE_BLOCKED for BLOCK")
        void shouldReturnRoleBlockedForBlock() {
            assertThat(ZeroTrustAction.BLOCK.getGrantedAuthority()).isEqualTo("ROLE_BLOCKED");
        }

        @Test
        @DisplayName("Should return ROLE_MFA_REQUIRED for CHALLENGE")
        void shouldReturnRoleMfaRequiredForChallenge() {
            assertThat(ZeroTrustAction.CHALLENGE.getGrantedAuthority()).isEqualTo("ROLE_MFA_REQUIRED");
        }

        @Test
        @DisplayName("Should return ROLE_REVIEW_REQUIRED for ESCALATE")
        void shouldReturnRoleReviewRequiredForEscalate() {
            assertThat(ZeroTrustAction.ESCALATE.getGrantedAuthority()).isEqualTo("ROLE_REVIEW_REQUIRED");
        }

        @Test
        @DisplayName("Should return ROLE_PENDING_ANALYSIS for PENDING_ANALYSIS")
        void shouldReturnRolePendingAnalysisForPendingAnalysis() {
            assertThat(ZeroTrustAction.PENDING_ANALYSIS.getGrantedAuthority()).isEqualTo("ROLE_PENDING_ANALYSIS");
        }
    }
}
