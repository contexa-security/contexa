package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacore.verification.capture.VerificationCaptureStoreOptions;
import io.contexa.contexacore.verification.evidence.DecisionPriorityCaptureSampling;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageAssembler;
import io.contexa.contexacore.verification.evidence.VersionChangeCaptureSampling;
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

    /**
     * R4-S6, K43: the decisions sealed in full after a start and after the prompt version decisions run changes; a
     * version a canary or a shadow runs beside it has a window of its own.
     */
    private int fullCaptureAfterChange = VersionChangeCaptureSampling.DEFAULT_FULL_CAPTURE_AFTER_CHANGE;

    /**
     * Plan 3.6: the packages sealed in one UTC day up to which every decision that stopped the request (CHALLENGE,
     * ESCALATE, BLOCK) and every allowed decision with a sign of risk is sealed, counted over the servers that share
     * the store; past it the day seals by the window and the share alone. 0 seals by the window and the share alone.
     */
    private int dailyLimit = DecisionPriorityCaptureSampling.DEFAULT_DAILY_LIMIT;

    /** Plan 3.6: the unknown decision facts from which an allowed decision counts as one with a sign of risk. */
    private int unknownFactThreshold = DecisionPriorityCaptureSampling.DEFAULT_UNKNOWN_FACT_THRESHOLD;

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

    public int getDailyLimit() {
        return dailyLimit;
    }

    public void setDailyLimit(int dailyLimit) {
        this.dailyLimit = dailyLimit;
    }

    public int getUnknownFactThreshold() {
        return unknownFactThreshold;
    }

    public void setUnknownFactThreshold(int unknownFactThreshold) {
        this.unknownFactThreshold = unknownFactThreshold;
    }

    public VerificationCaptureStoreOptions storeOptions() {
        return new VerificationCaptureStoreOptions(snapshotTtl, maxPendingSnapshots, maxCompletedSnapshots);
    }

    private final Retention retention = new Retention();

    public Retention getRetention() {
        return retention;
    }

    /**
     * How long a sealed package is kept before the retention job deletes it (R4-S4, D-C): one period for every
     * package, whatever a prompt inspection found in it.
     */
    public static class Retention {

        private Duration period = SealedEvidencePackageAssembler.DEFAULT_RETENTION;

        /**
         * No package is removed by this period any more. Earlier versions removed a package whose latest inspection
         * found nothing wrong once it was older than this (R4-S5), from inside the chain of sealed packages; the
         * integrity check still reads a package missing before one older than the shorter of this and {@link #period}
         * as that removal (SealedEvidenceStoreAutoConfiguration).
         */
        private Duration cleanPeriod = Duration.ofDays(30);

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
