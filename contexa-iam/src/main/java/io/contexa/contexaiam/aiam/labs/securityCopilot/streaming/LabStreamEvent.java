package io.contexa.contexaiam.aiam.labs.securityCopilot.streaming;

import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
public class LabStreamEvent {
    private final String labName;           
    private final String labDisplayName;    
    private final String content;           
    private final int priority;             
    private final long sequence;            
    private final LocalDateTime timestamp;  
    private final EventType eventType;      
    private final boolean isComplete;       

    public enum EventType {
        START,      
        PROGRESS,   
        RESULT,     
        COMPLETE,   
        ERROR       
    }

    public String getFormattedMessage() {
        if (eventType == EventType.START) {
            return String.format("\n\n=== [%s] 분석 시작 ===\n", labDisplayName);
        } else if (eventType == EventType.COMPLETE) {
            return String.format("\n[%s 분석 완료]\n\n", labDisplayName);
        } else if (eventType == EventType.ERROR) {
            return String.format("\n[%s] %s\n", labDisplayName, content);
        } else {
            
            return content;
        }
    }

    public long getSortWeight() {

        return (long) priority * 1000000L + sequence;
    }
}