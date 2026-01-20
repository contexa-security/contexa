package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import org.springframework.context.ApplicationEvent;


public class ProcessingCompletedEvent extends ApplicationEvent {

    private final SecurityEvent originalEvent;
    private final ProcessingResult result;
    private final ProcessingMode mode;
    private final ProcessingLayer layer;
    private final long processingTimeMs;
    private final double accuracy;

    
    public ProcessingCompletedEvent(Object source, SecurityEvent originalEvent,
                                   ProcessingResult result, ProcessingMode mode,
                                   ProcessingLayer layer, long processingTimeMs,
                                   double accuracy) {
        super(source);
        this.originalEvent = originalEvent;
        this.result = result;
        this.mode = mode;
        this.layer = layer;
        this.processingTimeMs = processingTimeMs;
        this.accuracy = accuracy;
    }

    
    public ProcessingCompletedEvent(Object source, SecurityEvent originalEvent,
                                   ProcessingResult result, ProcessingMode mode,
                                   ProcessingLayer layer, long processingTimeMs) {
        this(source, originalEvent, result, mode, layer, processingTimeMs, 0.0);
    }

    
    public SecurityEvent getOriginalEvent() {
        return originalEvent;
    }

    public ProcessingResult getResult() {
        return result;
    }

    public ProcessingMode getMode() {
        return mode;
    }

    public ProcessingLayer getLayer() {
        return layer;
    }

    public long getProcessingTimeMs() {
        return processingTimeMs;
    }

    public double getAccuracy() {
        return accuracy;
    }

    
    public boolean isHotPath() {
        return mode == ProcessingMode.REALTIME_BLOCK;
    }

    
    public boolean isColdPath() {
        return mode == ProcessingMode.AI_ANALYSIS ||
               mode == ProcessingMode.SOAR_ORCHESTRATION ||
               mode == ProcessingMode.AWAIT_APPROVAL;
    }

    
    public boolean isHighValueForLearning() {
        
        if (layer.ordinal() >= ProcessingLayer.LAYER2.ordinal()) {
            return true;
        }

        
        if (result != null && result.isAnomaly()) {
            return true;
        }

        
        if (result != null && result.getThreatIndicators() != null &&
            !result.getThreatIndicators().isEmpty()) {
            return true;
        }

        
        if (result != null && result.isRequiresIncident()) {
            return true;
        }

        return false;
    }

    @Override
    public String toString() {
        return String.format("ProcessingCompletedEvent[eventId=%s, mode=%s, layer=%s, timeMs=%d, accuracy=%.2f, highValue=%s]",
            originalEvent != null ? originalEvent.getEventId() : "null",
            mode, layer, processingTimeMs, accuracy, isHighValueForLearning());
    }

    
    public enum ProcessingLayer {
        LAYER1("Layer1 - Fast Filter, Local Model (~100ms)"),
        LAYER2("Layer2 - Expert Analysis, High-Performance Model (~5s)"),
        UNKNOWN("Unknown Layer");

        private final String description;

        ProcessingLayer(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }

        
        public static ProcessingLayer fromLevel(int level) {
            switch (level) {
                case 1: return LAYER1;
                case 2: return LAYER2;
                default: return UNKNOWN;
            }
        }
    }
}
