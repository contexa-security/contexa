package io.contexa.contexacore.verification.capture;

import java.time.Duration;

/** Bounded lifecycle policy for pending and completed capture snapshots. */
public record VerificationCaptureStoreOptions(Duration snapshotTtl, int maxPending, int maxCompleted) {

    public VerificationCaptureStoreOptions {
        if (snapshotTtl == null || snapshotTtl.isZero() || snapshotTtl.isNegative()) {
            throw new IllegalArgumentException("snapshotTtl must be positive");
        }
        if (maxPending < 1 || maxCompleted < 1) {
            throw new IllegalArgumentException("capture store limits must be positive");
        }
    }

    public static VerificationCaptureStoreOptions defaults() {
        return new VerificationCaptureStoreOptions(Duration.ofMinutes(10), 1_000, 1_000);
    }
}