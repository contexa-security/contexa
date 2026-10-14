package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacore.verification.capture.VerificationCaptureStoreOptions;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageAssembler;
import io.contexa.contexacore.verification.evidence.VersionChangeCaptureSampling;
import io.contexa.contexacore.verification.inspection.PromptInspectionCleanPackageRetentionScheduler;
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

    /** R4-S6, decision D-B: the share of requests sealed outside the window after a change. */
    private int samplePercent = VersionChangeCaptureSampling.DEFAULT_SAMPLE_PERCENT;

    /** R4-S6: the decisions sealed in full after a start or a change of the active prompt bundle. */
    private int fullCaptureAfterChange = VersionChangeCaptureSampling.DEFAULT_FULL_CAPTURE_AFTER_CHANGE;

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

    public int getSamplePercent() {
        return samplePercent;
    }

    public void setSamplePercent(int samplePercent) {
        this.samplePercent = samplePercent;
    }

    public int getFullCaptureAfterChange() {
        return fullCaptureAfterChange;
    }

    public void setFullCaptureAfterChange(int fullCaptureAfterChange) {
        this.fullCaptureAfterChange = fullCaptureAfterChange;
    }

    public VerificationCaptureStoreOptions storeOptions() {
        return new VerificationCaptureStoreOptions(snapshotTtl, maxPendingSnapshots, maxCompletedSnapshots);
    }

    private final Retention retention = new Retention();

    public Retention getRetention() {
        return retention;
    }

    /**
     * How long a sealed package is kept before the retention job deletes it (R4-S4, D-C), and how long one whose
     * latest inspection found nothing wrong is kept (R4-S5).
     */
    public static class Retention {

        private Duration period = SealedEvidencePackageAssembler.DEFAULT_RETENTION;

        private Duration cleanPeriod = PromptInspectionCleanPackageRetentionScheduler.DEFAULT_CLEAN_PERIOD;

        public Duration getPeriod() {
            return period;
        }

        public void setPeriod(Duration period) {
            this.period = period;
        }

        public Duration getCleanPeriod() {
            return cleanPeriod;
        }

        public void setCleanPeriod(Duration cleanPeriod) {
            this.cleanPeriod = cleanPeriod;
        }
    }
}
