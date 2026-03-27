package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageLevel;
import io.contexa.contexacommon.security.bridge.coverage.MissingBridgeContext;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class BridgeCoverageEvaluatorTest {

    private final BridgeCoverageEvaluator evaluator = new BridgeCoverageEvaluator();

    @Test
    void shouldResolveDelegationCoverageWhenAuthenticationAuthorizationAndDelegationExist() {
        AuthenticationStamp authenticationStamp = new AuthenticationStamp(
                "alice", "Alice", "USER", true, "JWT", "HEADER", "HIGH", true,
                Instant.parse("2026-03-23T10:15:30Z"), "session-1", List.of("ROLE_USER"), Map.of()
        );
        AuthorizationStamp authorizationStamp = new AuthorizationStamp(
                "alice", "/reports/export", "POST", AuthorizationEffect.ALLOW, true,
                List.of("report:export"), "policy-1", null, "HEADER", Instant.now(),
                List.of("ROLE_USER"), List.of("REPORT_EXPORT"), Map.of()
        );
        DelegationStamp delegationStamp = new DelegationStamp(
                "alice", "agent-1", true, "objective-1", "Export monthly report",
                List.of("EXPORT"), List.of("report:monthly"), true, false, null, Map.of()
        );

        var report = evaluator.evaluate(authenticationStamp, authorizationStamp, delegationStamp);

        assertThat(report.level()).isEqualTo(BridgeCoverageLevel.DELEGATION_CONTEXT);
        assertThat(report.score()).isEqualTo(90);
        assertThat(report.purpose()).isEqualTo("BRIDGE_COMPLETENESS_ONLY");
        assertThat(report.summary()).contains("delegated execution context");
        assertThat(report.remediationHints()).isEmpty();
        assertThat(report.missingContexts()).doesNotContain(MissingBridgeContext.AUTHENTICATION, MissingBridgeContext.AUTHORIZATION, MissingBridgeContext.DELEGATION);
    }

    @Test
    void shouldExposeRemediationHintsWhenAuthorizationContextIsMissing() {
        AuthenticationStamp authenticationStamp = new AuthenticationStamp(
                "alice", "Alice", "USER", true, "SESSION", "SESSION", "STANDARD", false,
                Instant.parse("2026-03-23T10:15:30Z"), "session-1", List.of("ROLE_USER"), Map.of()
        );

        var report = evaluator.evaluate(authenticationStamp, null, null);

        assertThat(report.level()).isEqualTo(BridgeCoverageLevel.AUTHENTICATION_ONLY);
        assertThat(report.score()).isEqualTo(40);
        assertThat(report.summary()).contains("Bridge completeness reached authentication");
        assertThat(report.missingContexts()).contains(MissingBridgeContext.AUTHORIZATION);
        assertThat(report.missingContexts()).doesNotContain(MissingBridgeContext.DELEGATION);
        assertThat(report.remediationHints()).anyMatch(value -> value.contains("authorization stamp"));
    }

    @Test
    void shouldLowerAuthorizationCoverageWhenOnlyAuthenticationDerivedAuthorizationExists() {
        AuthenticationStamp authenticationStamp = new AuthenticationStamp(
                "alice", "Alice", "USER", true, "JWT", "HEADER", "HIGH", true,
                Instant.parse("2026-03-23T10:15:30Z"), "session-1", List.of("ROLE_USER", "REPORT_EXPORT"), Map.of()
        );
        AuthorizationStamp authorizationStamp = new AuthorizationStamp(
                "alice", "/reports/export", "POST", AuthorizationEffect.UNKNOWN, false,
                List.of(), null, null, "AUTHENTICATION_DERIVED", Instant.now(),
                List.of("ROLE_USER"), List.of("ROLE_USER", "REPORT_EXPORT"), Map.of()
        );

        var report = evaluator.evaluate(authenticationStamp, authorizationStamp, null);

        assertThat(report.level()).isEqualTo(BridgeCoverageLevel.AUTHORIZATION_CONTEXT);
        assertThat(report.score()).isEqualTo(58);
        assertThat(report.missingContexts()).contains(MissingBridgeContext.AUTHORIZATION_EFFECT);
        assertThat(report.summary()).contains("partial authorization context");
        assertThat(report.remediationHints()).anyMatch(value -> value.contains("authorization effect"));
    }

    @Test
    void shouldKeepAuthorizationCoverageWhenDelegationIsNotUsed() {
        AuthenticationStamp authenticationStamp = new AuthenticationStamp(
                "alice", "Alice", "USER", true, "JWT", "SECURITY_CONTEXT", "HIGH", true,
                Instant.parse("2026-03-23T10:15:30Z"), "session-1", List.of("ROLE_USER"), Map.of()
        );
        AuthorizationStamp authorizationStamp = new AuthorizationStamp(
                "alice", "/reports/view", "GET", AuthorizationEffect.ALLOW, false,
                List.of("report:view"), "policy-1", null, "SECURITY_CONTEXT", Instant.now(),
                List.of("ROLE_USER"), List.of("REPORT_VIEW"), Map.of()
        );

        var report = evaluator.evaluate(authenticationStamp, authorizationStamp, null);

        assertThat(report.level()).isEqualTo(BridgeCoverageLevel.AUTHORIZATION_CONTEXT);
        assertThat(report.score()).isEqualTo(75);
        assertThat(report.missingContexts()).doesNotContain(MissingBridgeContext.DELEGATION);
        assertThat(report.summary()).contains("Bridge completeness reached authentication and authorization context");
    }
}
