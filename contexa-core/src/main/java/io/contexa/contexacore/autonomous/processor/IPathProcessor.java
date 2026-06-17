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
package io.contexa.contexacore.autonomous.processor;

import io.contexa.contexacore.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;

public interface IPathProcessor {

    ProcessingResult processEvent(SecurityEvent event, double riskScore);

    ProcessingMode getProcessingMode();

    String getProcessorName();

    default boolean isReady() {
        return true;
    }

    default ProcessorStatistics getStatistics() {
        return ProcessorStatistics.empty();
    }

    class ProcessorStatistics {
        private long processedCount;
        private double averageProcessingTime;
        private long lastProcessedTimestamp;

        public static ProcessorStatistics empty() {
            return new ProcessorStatistics();
        }

        public long getProcessedCount() {
            return processedCount;
        }

        public void setProcessedCount(long processedCount) {
            this.processedCount = processedCount;
        }

        public double getAverageProcessingTime() {
            return averageProcessingTime;
        }

        public void setAverageProcessingTime(double averageProcessingTime) {
            this.averageProcessingTime = averageProcessingTime;
        }

        public long getLastProcessedTimestamp() {
            return lastProcessedTimestamp;
        }

        public void setLastProcessedTimestamp(long lastProcessedTimestamp) {
            this.lastProcessedTimestamp = lastProcessedTimestamp;
        }
    }
}
