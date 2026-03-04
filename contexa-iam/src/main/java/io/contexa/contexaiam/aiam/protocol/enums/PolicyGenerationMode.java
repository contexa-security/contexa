package io.contexa.contexaiam.aiam.protocol.enums;

public enum PolicyGenerationMode {
    
    QUICK("Quick Generation", "Rapid policy generation using basic templates"),

    AI_ASSISTED("AI-Assisted Generation", "Policy generation mode with active AI assistance"),

    PRECISE("Precise Generation", "Precise policy generation through full AI analysis"),

    EXPERIMENTAL("Experimental Generation", "Experimental policy generation applying latest AI techniques");
    
    private final String displayName;
    private final String description;
    
    PolicyGenerationMode(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }
} 