package io.contexa.contexacore.autonomous.tiered.template;


public enum BaselineStatus {

    
    ESTABLISHED("Available", "User baseline data is available for comparison"),

    
    NEW_USER("[NEW_USER] No baseline established", "Cannot compare against historical patterns"),

    
    NOT_LOADED("[NO_DATA] Baseline available but not loaded", "Anomaly detection unavailable"),

    
    SERVICE_UNAVAILABLE("[SERVICE_UNAVAILABLE] Baseline service not available", "Anomaly detection unavailable"),

    
    MISSING_USER_ID("[NO_USER_ID] Cannot lookup baseline without user identifier", "Anomaly detection unavailable"),

    
    ANALYSIS_UNAVAILABLE("[NO_DATA] Behavior analysis unavailable", "ESCALATE recommended");

    private final String statusLabel;
    private final String impactDescription;

    BaselineStatus(String statusLabel, String impactDescription) {
        this.statusLabel = statusLabel;
        this.impactDescription = impactDescription;
    }

    
    public String getStatusLabel() {
        return statusLabel;
    }

    
    public String getImpactDescription() {
        return impactDescription;
    }

    
    public boolean isZeroTrustViolation() {
        return this != ESTABLISHED;
    }

    
    public String buildPromptSection(String baselineContext) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== BASELINE ===\n");
        sb.append("STATUS: ").append(statusLabel).append("\n");

        if (this == ESTABLISHED && baselineContext != null) {
            sb.append(baselineContext).append("\n");
        } else {
            sb.append("IMPACT: ").append(impactDescription).append("\n");
        }

        return sb.toString();
    }
}
