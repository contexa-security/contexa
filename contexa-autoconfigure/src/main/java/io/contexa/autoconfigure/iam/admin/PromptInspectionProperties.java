package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacore.verification.inspection.PromptInspectionScheduler;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * OSS prompt inspection settings. The automatic round inspects every sealed package once by default; the interval
 * and the first delay are read by the round's schedule.
 */
@ConfigurationProperties("contexa.prompt-inspection")
public class PromptInspectionProperties {

    private boolean enabled = true;
    private Duration interval = Duration.parse(PromptInspectionScheduler.DEFAULT_INTERVAL);
    private Duration initialDelay = Duration.parse(PromptInspectionScheduler.DEFAULT_INITIAL_DELAY);
    private int batchSize = 50;
    private int samplePercent = 100;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Duration getInterval() {
        return interval;
    }

    public void setInterval(Duration interval) {
        this.interval = interval;
    }

    public Duration getInitialDelay() {
        return initialDelay;
    }

    public void setInitialDelay(Duration initialDelay) {
        this.initialDelay = initialDelay;
    }

    public int getBatchSize() {
        return batchSize;
    }

    public void setBatchSize(int batchSize) {
        this.batchSize = batchSize;
    }

    public int getSamplePercent() {
        return samplePercent;
    }

    public void setSamplePercent(int samplePercent) {
        this.samplePercent = samplePercent;
    }
}
