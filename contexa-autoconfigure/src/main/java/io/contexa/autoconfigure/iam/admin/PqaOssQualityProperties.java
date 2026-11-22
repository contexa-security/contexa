/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacore.std.components.prompt.quality.QualityGateMode;
import io.contexa.contexacore.std.components.prompt.quality.QualityGatePolicy;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSettings;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSource;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.QualityScheduledMeasurement;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * The settings of the prompt quality (quality plan 3.2, 3.3, 3.4): the labelled cases, the measurements, and the
 * quality gate the release gate applies when a version of the security decision is used for decisions or started as a
 * canary.
 */
@ConfigurationProperties("contexa.pqa.oss.quality")
public class PqaOssQualityProperties {

    /**
     * Quality plan 3.2: whether a labelled case and each change of its answer wait until an administrator other than
     * the one who set the answer confirms it before the case enters a published set. Turn it off for an installation
     * with one administrator: cases are then confirmed as they are submitted.
     */
    private boolean twoPersonConfirmation = true;

    private final Measurement measurement = new Measurement();

    private final Gate gate = new Gate();

    private final Remeasure remeasure = new Remeasure();

    public Measurement getMeasurement() {
        return measurement;
    }

    public Remeasure getRemeasure() {
        return remeasure;
    }

    public Gate getGate() {
        return gate;
    }

    public boolean isTwoPersonConfirmation() {
        return twoPersonConfirmation;
    }

    public void setTwoPersonConfirmation(boolean twoPersonConfirmation) {
        this.twoPersonConfirmation = twoPersonConfirmation;
    }

    /**
     * Quality plan 3.6: the version in use measured again on schedule and when the model setting changed, and told
     * when it came out worse than its measurement before.
     */
    public static class Remeasure {

        /**
         * When the version in use is measured again, a Spring cron expression in UTC; "-" turns the schedule off.
         * Each run measures it anew (quality P32), with no kept answer used again: about 210 model calls on the
         * default case set.
         */
        private String cron = QualityScheduledMeasurement.DEFAULT_CRON;

        public String getCron() {
            return cron;
        }

        public void setCron(String cron) {
            this.cron = cron;
        }
    }

    /** How the measurements run (quality plan 3.3). */
    public static class Measurement {

        private static final PromptQualityMeasurements.Settings DEFAULTS = PromptQualityMeasurements.Settings.DEFAULTS;

        /** How many times each case is run when a measurement asks for no number. */
        private int repeats = DEFAULTS.repeats();

        /** How many replays of one measurement run at once, behind the decisions at the model server's gate. */
        private int concurrency = DEFAULTS.concurrency();

        /** How many more times a replay the model server did not answer (busy, unreachable, a time limit) is asked. */
        private int retries = DEFAULTS.retries();

        /** The wait before the first such retry; the second waits twice as long, and so on. */
        private Duration retryDelay = DEFAULTS.retryDelay();

        /** The most model calls one measurement makes; 0 sets no limit. */
        private int callLimit = DEFAULTS.callLimit();

        /** How often the server running a measurement renews its lock and heartbeat, and the others look for work. */
        private Duration heartbeat = DEFAULTS.heartbeat();

        public PromptQualityMeasurements.Settings toSettings() {
            return new PromptQualityMeasurements.Settings(repeats, concurrency, retries, retryDelay, callLimit,
                    heartbeat);
        }

        public int getRepeats() {
            return repeats;
        }

        public void setRepeats(int repeats) {
            this.repeats = repeats;
        }

        public int getConcurrency() {
            return concurrency;
        }

        public void setConcurrency(int concurrency) {
            this.concurrency = concurrency;
        }

        public int getRetries() {
            return retries;
        }

        public void setRetries(int retries) {
            this.retries = retries;
        }

        public Duration getRetryDelay() {
            return retryDelay;
        }

        public void setRetryDelay(Duration retryDelay) {
            this.retryDelay = retryDelay;
        }

        public int getCallLimit() {
            return callLimit;
        }

        public void setCallLimit(int callLimit) {
            this.callLimit = callLimit;
        }

        public Duration getHeartbeat() {
            return heartbeat;
        }

        public void setHeartbeat(Duration heartbeat) {
            this.heartbeat = heartbeat;
        }
    }

    /**
     * Quality plan 3.4, 5 step 5: the quality gate. It goes in as a warning; an installation blocks with it once the
     * reproducibility and discrimination checks of plan 6 have passed. A value outside its range stops the start.
     */
    public static class Gate {

        private static final QualityGateSettings DEFAULTS = QualityGateSettings.defaults();

        /** WARN applies a blocked verdict as a warning (the default); BLOCK blocks, and a reason overrides it. */
        private QualityGateMode mode = QualityGateMode.WARN;

        /** The largest share of answers decided without the model. */
        private double modelLessLimit = DEFAULTS.modelLessLimit();

        /** The level of the exact tests that say a rate grew. */
        private double significance = DEFAULTS.significance();

        /** The distinct roots of cases that must be stopped needed to tell two versions apart. */
        private int minimumStopRoots = DEFAULTS.minimumStopRoots();

        /** The distinct roots of cases that must be allowed needed to tell two versions apart. */
        private int minimumAllowRoots = DEFAULTS.minimumAllowRoots();

        /**
         * Quality P8: how far the friction of the candidate may grow over that of the version in use, as a difference
         * of the two rates (0.20, the default, is 20 percentage points), before the gate blocks whatever the
         * significance.
         */
        private double frictionIncreaseLimit = DEFAULTS.frictionIncreaseLimit();

        /** The quality gate with the measurements of the source, these thresholds and this mode. */
        public QualityGatePolicy policy(QualityGateSource source) {
            return new QualityGatePolicy(source, mode, settings());
        }

        /** These thresholds; a value outside its range is refused. */
        public QualityGateSettings settings() {
            return new QualityGateSettings(modelLessLimit, significance, minimumStopRoots, minimumAllowRoots,
                    frictionIncreaseLimit);
        }

        public QualityGateMode getMode() {
            return mode;
        }

        public void setMode(QualityGateMode mode) {
            this.mode = mode;
        }

        public double getModelLessLimit() {
            return modelLessLimit;
        }

        public void setModelLessLimit(double modelLessLimit) {
            this.modelLessLimit = modelLessLimit;
        }

        public double getSignificance() {
            return significance;
        }

        public void setSignificance(double significance) {
            this.significance = significance;
        }

        public int getMinimumStopRoots() {
            return minimumStopRoots;
        }

        public void setMinimumStopRoots(int minimumStopRoots) {
            this.minimumStopRoots = minimumStopRoots;
        }

        public int getMinimumAllowRoots() {
            return minimumAllowRoots;
        }

        public void setMinimumAllowRoots(int minimumAllowRoots) {
            this.minimumAllowRoots = minimumAllowRoots;
        }

        public double getFrictionIncreaseLimit() {
            return frictionIncreaseLimit;
        }

        public void setFrictionIncreaseLimit(double frictionIncreaseLimit) {
            this.frictionIncreaseLimit = frictionIncreaseLimit;
        }
    }
}
