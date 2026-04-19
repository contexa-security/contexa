package io.contexa.contexacore.autonomous.tiered.prompt;

public enum BaselineStatus {

    ESTABLISHED("Available", "User baseline data is available for comparison"),

    PROVISIONAL("PROVISIONAL", "Personal baseline evidence is forming but is not yet stable enough to prove normal behavior"),

    SPARSE_PERSONAL_HISTORY("SPARSE_PERSONAL_HISTORY", "User is known but personal behavioral history remains too sparse to establish a personal baseline"),

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
}
