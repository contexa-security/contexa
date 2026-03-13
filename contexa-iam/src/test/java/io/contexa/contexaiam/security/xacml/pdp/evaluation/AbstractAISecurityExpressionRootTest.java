package io.contexa.contexaiam.security.xacml.pdp.evaluation;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AbstractAISecurityExpressionRootTest {

    @Mock
    private Authentication authentication;

    @Mock
    private AuthorizationContext authorizationContext;

    @Mock
    private AuditLogRepository auditLogRepository;

    @Mock
    private ZeroTrustActionRepository actionRedisRepository;

    private TestAISecurityExpressionRoot expressionRoot;

    // Concrete subclass overriding getCurrentAction for controlled testing
    static class TestAISecurityExpressionRoot extends AbstractAISecurityExpressionRoot {

        private ZeroTrustAction actionOverride;

        TestAISecurityExpressionRoot(Authentication authentication,
                                     AuthorizationContext authorizationContext,
                                     AuditLogRepository auditLogRepository,
                                     ZeroTrustActionRepository actionRedisRepository) {
            super(authentication, authorizationContext, auditLogRepository, actionRedisRepository);
        }

        void setActionOverride(ZeroTrustAction action) {
            this.actionOverride = action;
        }

        @Override
        protected ZeroTrustAction getCurrentAction() {
            return actionOverride;
        }

        String callExtractUserId() {
            return extractUserId();
        }
    }

    @BeforeEach
    void setUp() {
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getName()).thenReturn("testUser");
        expressionRoot = new TestAISecurityExpressionRoot(
                authentication, authorizationContext, auditLogRepository, actionRedisRepository);
        expressionRoot.setActionOverride(ZeroTrustAction.ALLOW);
    }

    @Nested
    @DisplayName("isAllowed")
    class IsAllowedTest {

        @Test
        @DisplayName("Should return true when action is ALLOW")
        void shouldReturnTrueForAllow() {
            expressionRoot.setActionOverride(ZeroTrustAction.ALLOW);

            assertThat(expressionRoot.isAllowed()).isTrue();
        }

        @Test
        @DisplayName("Should return false when action is not ALLOW")
        void shouldReturnFalseForNonAllow() {
            expressionRoot.setActionOverride(ZeroTrustAction.BLOCK);

            assertThat(expressionRoot.isAllowed()).isFalse();
        }
    }

    @Nested
    @DisplayName("isBlocked")
    class IsBlockedTest {

        @Test
        @DisplayName("Should return true when action is BLOCK")
        void shouldReturnTrueForBlock() {
            expressionRoot.setActionOverride(ZeroTrustAction.BLOCK);

            assertThat(expressionRoot.isBlocked()).isTrue();
        }

        @Test
        @DisplayName("Should return false when action is ALLOW")
        void shouldReturnFalseForAllow() {
            expressionRoot.setActionOverride(ZeroTrustAction.ALLOW);

            assertThat(expressionRoot.isBlocked()).isFalse();
        }
    }

    @Nested
    @DisplayName("needsChallenge")
    class NeedsChallengeTest {

        @Test
        @DisplayName("Should return true when action is CHALLENGE")
        void shouldReturnTrueForChallenge() {
            expressionRoot.setActionOverride(ZeroTrustAction.CHALLENGE);

            assertThat(expressionRoot.needsChallenge()).isTrue();
        }

        @Test
        @DisplayName("Should return false when action is ALLOW")
        void shouldReturnFalseForAllow() {
            expressionRoot.setActionOverride(ZeroTrustAction.ALLOW);

            assertThat(expressionRoot.needsChallenge()).isFalse();
        }
    }

    @Nested
    @DisplayName("needsEscalation")
    class NeedsEscalationTest {

        @Test
        @DisplayName("Should return true when action is ESCALATE")
        void shouldReturnTrueForEscalate() {
            expressionRoot.setActionOverride(ZeroTrustAction.ESCALATE);

            assertThat(expressionRoot.needsEscalation()).isTrue();
        }

        @Test
        @DisplayName("Should return false when action is ALLOW")
        void shouldReturnFalseForAllow() {
            expressionRoot.setActionOverride(ZeroTrustAction.ALLOW);

            assertThat(expressionRoot.needsEscalation()).isFalse();
        }
    }

    @Nested
    @DisplayName("isPendingAnalysis")
    class IsPendingAnalysisTest {

        @Test
        @DisplayName("Should return true when action is PENDING_ANALYSIS")
        void shouldReturnTrueForPendingAnalysis() {
            expressionRoot.setActionOverride(ZeroTrustAction.PENDING_ANALYSIS);

            assertThat(expressionRoot.isPendingAnalysis()).isTrue();
        }
    }

    @Nested
    @DisplayName("hasAction")
    class HasActionTest {

        @Test
        @DisplayName("Should return true when action string matches current action")
        void shouldReturnTrueWhenActionMatches() {
            expressionRoot.setActionOverride(ZeroTrustAction.ALLOW);

            assertThat(expressionRoot.hasAction("ALLOW")).isTrue();
        }

        @Test
        @DisplayName("Should return true for shorthand action string")
        void shouldReturnTrueForShorthand() {
            expressionRoot.setActionOverride(ZeroTrustAction.ALLOW);

            assertThat(expressionRoot.hasAction("A")).isTrue();
        }

        @Test
        @DisplayName("Should return false when action string does not match")
        void shouldReturnFalseWhenActionDoesNotMatch() {
            expressionRoot.setActionOverride(ZeroTrustAction.ALLOW);

            assertThat(expressionRoot.hasAction("BLOCK")).isFalse();
        }
    }

    @Nested
    @DisplayName("hasActionIn")
    class HasActionInTest {

        @Test
        @DisplayName("Should return true when current action is in the allowed list")
        void shouldReturnTrueWhenActionInList() {
            expressionRoot.setActionOverride(ZeroTrustAction.CHALLENGE);

            assertThat(expressionRoot.hasActionIn("ALLOW", "CHALLENGE")).isTrue();
        }

        @Test
        @DisplayName("Should return false when current action is not in the allowed list")
        void shouldReturnFalseWhenActionNotInList() {
            expressionRoot.setActionOverride(ZeroTrustAction.BLOCK);

            assertThat(expressionRoot.hasActionIn("ALLOW", "CHALLENGE")).isFalse();
        }

        @Test
        @DisplayName("Should support shorthand action strings")
        void shouldSupportShorthandStrings() {
            expressionRoot.setActionOverride(ZeroTrustAction.BLOCK);

            assertThat(expressionRoot.hasActionIn("A", "B")).isTrue();
        }
    }

    @Nested
    @DisplayName("hasActionOrDefault")
    class HasActionOrDefaultTest {

        @Test
        @DisplayName("Should use current action when not PENDING_ANALYSIS")
        void shouldUseCurrentActionWhenNotPending() {
            expressionRoot.setActionOverride(ZeroTrustAction.ALLOW);

            assertThat(expressionRoot.hasActionOrDefault("BLOCK", "ALLOW", "CHALLENGE")).isTrue();
        }

        @Test
        @DisplayName("Should use default action when current is PENDING_ANALYSIS")
        void shouldUseDefaultActionWhenPending() {
            expressionRoot.setActionOverride(ZeroTrustAction.PENDING_ANALYSIS);

            // Default is "ALLOW", allowed list contains "ALLOW"
            assertThat(expressionRoot.hasActionOrDefault("ALLOW", "ALLOW", "CHALLENGE")).isTrue();
        }

        @Test
        @DisplayName("Should return false when default is not in allowed list and current is PENDING")
        void shouldReturnFalseWhenDefaultNotInAllowedList() {
            expressionRoot.setActionOverride(ZeroTrustAction.PENDING_ANALYSIS);

            // Default is "BLOCK", allowed list is "ALLOW", "CHALLENGE"
            assertThat(expressionRoot.hasActionOrDefault("BLOCK", "ALLOW", "CHALLENGE")).isFalse();
        }

        @Test
        @DisplayName("Should return false when current action not in allowed list and not PENDING")
        void shouldReturnFalseWhenCurrentNotInList() {
            expressionRoot.setActionOverride(ZeroTrustAction.ESCALATE);

            assertThat(expressionRoot.hasActionOrDefault("ALLOW", "ALLOW", "CHALLENGE")).isFalse();
        }
    }

    @Nested
    @DisplayName("extractUserId")
    class ExtractUserIdTest {

        @Test
        @DisplayName("Should return username from authentication")
        void shouldReturnUsernameFromAuth() {
            assertThat(expressionRoot.callExtractUserId()).isEqualTo("testUser");
        }

        @Test
        @DisplayName("Should return null when authentication is not authenticated")
        void shouldReturnNullWhenNotAuthenticated() {
            when(authentication.isAuthenticated()).thenReturn(false);
            TestAISecurityExpressionRoot realRoot = new TestAISecurityExpressionRoot(
                    authentication, authorizationContext, auditLogRepository, actionRedisRepository);

            assertThat(realRoot.callExtractUserId()).isNull();
        }
    }
}
