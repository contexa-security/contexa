package io.contexa.contexacore.autonomous.security.processor;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
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