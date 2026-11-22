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

import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * The settings of the prompt quality measurement (quality plan 3.2, 3.3): the labelled cases and the measurements.
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

    public Measurement getMeasurement() {
        return measurement;
    }

    public boolean isTwoPersonConfirmation() {
        return twoPersonConfirmation;
    }

    public void setTwoPersonConfirmation(boolean twoPersonConfirmation) {
        this.twoPersonConfirmation = twoPersonConfirmation;
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
}
