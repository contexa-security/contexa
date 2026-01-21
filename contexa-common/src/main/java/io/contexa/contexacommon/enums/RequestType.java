package io.contexa.contexacommon.enums;

import lombok.Getter;


@Getter
public enum RequestType {
    QUERY("Query", "Data query request"),
    COMMAND("Command", "System state change request"),
    ANALYSIS("Analysis", "Data analysis request"),
    GENERATION("Generation", "Content generation request"),
    VALIDATION("Validation", "Data validation request"),
    OPTIMIZATION("Optimization", "Performance optimization request"),
    MONITORING("Monitoring", "System monitoring request"),
    THREAT_RESPONSE("Threat Response", "AI-based threat response plan generation and execution request");
    
    private final String displayName;
    private final String description;
    
    RequestType(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }
}