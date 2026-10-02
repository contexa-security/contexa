package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacore.verification.capture.VerificationCaptureStoreOptions;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * OSS sealed evidence capture settings. Capture runs only while Enterprise is disabled.
 */
@ConfigurationProperties("contexa.pqa.oss.sealed-evidence")
public class PqaOssSealedEvidenceCaptureProperties {

    private static final VerificationCaptureStoreOptions DEFAULT_STORE_OPTIONS = VerificationCaptureStoreOptions.defaults();

    private boolean captureEnabled = true;

    private Duration snapshotTtl = DEFAULT_STORE_OPTIONS.snapshotTtl();

    private int maxPendingSnapshots = DEFAULT_STORE_OPTIONS.maxPending();

    private int maxCompletedSnapshots = DEFAULT_STORE_OPTIONS.maxCompleted();

    public boolean isCaptureEnabled() {
        return captureEnabled;
    }

    public void setCaptureEnabled(boolean captureEnabled) {
        this.captureEnabled = captureEnabled;
    }

    public Duration getSnapshotTtl() {
        return snapshotTtl;
    }

    public void setSnapshotTtl(Duration snapshotTtl) {
        this.snapshotTtl = snapshotTtl;
    }

    public int getMaxPendingSnapshots() {
        return maxPendingSnapshots;
    }

    public void setMaxPendingSnapshots(int maxPendingSnapshots) {
        this.maxPendingSnapshots = maxPendingSnapshots;
    }

    public int getMaxCompletedSnapshots() {
        return maxCompletedSnapshots;
    }

    public void setMaxCompletedSnapshots(int maxCompletedSnapshots) {
        this.maxCompletedSnapshots = maxCompletedSnapshots;
    }

    public VerificationCaptureStoreOptions storeOptions() {
        return new VerificationCaptureStoreOptions(snapshotTtl, maxPendingSnapshots, maxCompletedSnapshots);
    }
}
