package io.contexa.contexacore.verification.runtime.longhorizon;

import io.contexa.contexacore.verification.runtime.*;

import java.time.Duration;

final class OfficialVerificationLongHorizonExecutionSupport {

    private static final Duration PROBE_TIMEOUT = Duration.ofSeconds(12);
    private static final Duration ARTIFACT_TIMEOUT = Duration.ofSeconds(3);
    private static final Duration REPOSITORY_DECISION_TIMEOUT = Duration.ofMillis(250);
    private static final long MAX_INTER_ROUND_DELAY_MS = 50L;
    private static final long MIN_NON_TERMINAL_SETTLE_DELAY_MS = 50L;
    private static final long MAX_NON_TERMINAL_SETTLE_DELAY_MS = 100L;

    private OfficialVerificationLongHorizonExecutionSupport() {
    }

    static Duration probeTimeout() {
        return PROBE_TIMEOUT;
    }

    static Duration artifactTimeout() {
        return ARTIFACT_TIMEOUT;
    }

    static Duration repositoryDecisionTimeout() {
        return REPOSITORY_DECISION_TIMEOUT;
    }

    static long interRoundDelayMs(long configuredCooldownBeforeRoundMs) {
        if (configuredCooldownBeforeRoundMs <= 0L) {
            return 0L;
        }
        return Math.min(configuredCooldownBeforeRoundMs, MAX_INTER_ROUND_DELAY_MS);
    }

    static long nonTerminalSettleDelayMs(long configuredCooldownBeforeRoundMs) {
        long scaledDelay = configuredCooldownBeforeRoundMs <= 0L
                ? MIN_NON_TERMINAL_SETTLE_DELAY_MS
                : Math.max(configuredCooldownBeforeRoundMs / 10L, MIN_NON_TERMINAL_SETTLE_DELAY_MS);
        return Math.min(scaledDelay, MAX_NON_TERMINAL_SETTLE_DELAY_MS);
    }
}