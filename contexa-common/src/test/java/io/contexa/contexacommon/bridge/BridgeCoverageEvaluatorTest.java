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
        assertThat(report.missingContexts()).doesNotContain(MissingBridgeContext.AUTHENTICATION, MissingBridgeContext.AUTHORIZATION);
    }
}
