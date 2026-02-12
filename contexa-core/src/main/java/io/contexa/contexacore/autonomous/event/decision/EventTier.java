package io.contexa.contexacore.autonomous.event.decision;

import io.contexa.contexacommon.enums.ZeroTrustAction;

public enum EventTier {

    CRITICAL(0.8, 1.0, 1.0, true),

    HIGH(0.6, 0.8, 0.8, false),

    MEDIUM(0.4, 0.6, 0.5, false),

    LOW(0.2, 0.4, 0.2, false),

    BENIGN(0.0, 0.2, 0.1, false);

    private final double minRisk;
    private final double maxRisk;
    private final double baseSamplingRate;
    private final boolean immediatePublishing;

    EventTier(double minRisk, double maxRisk, double baseSamplingRate, boolean immediatePublishing) {
        this.minRisk = minRisk;
        this.maxRisk = maxRisk;
        this.baseSamplingRate = baseSamplingRate;
        this.immediatePublishing = immediatePublishing;
    }

    public static EventTier fromAction(ZeroTrustAction action, Boolean isAnomaly) {
        if (action == null) {
            return CRITICAL;
        }
        return switch (action) {
            case BLOCK -> CRITICAL;
            case ESCALATE -> HIGH;
            case CHALLENGE -> MEDIUM;
            case PENDING_ANALYSIS -> MEDIUM;
            case ALLOW -> Boolean.TRUE.equals(isAnomaly) ? LOW : BENIGN;
        };
    }

    public static EventTier fromAction(String action, Boolean isAnomaly) {
        if (action == null || action.isEmpty()) {
            return CRITICAL;
        }
        return fromAction(ZeroTrustAction.fromString(action), isAnomaly);
    }

    @Deprecated
    public static EventTier fromRiskScore(Double riskScore) {
        
        if (riskScore == null || Double.isNaN(riskScore)) {
            return CRITICAL;
        }

        double risk = Math.max(0.0, Math.min(1.0, riskScore));

        if (risk > 0.8) {
            return CRITICAL;
        } else if (risk > 0.6) {
            return HIGH;
        } else if (risk > 0.4) {
            return MEDIUM;
        } else if (risk > 0.2) {
            return LOW;
        } else {
            return BENIGN;
        }
    }

    public boolean requiresImmediatePublishing() {
        return immediatePublishing;
    }

    public double getBaseSamplingRate() {
        return baseSamplingRate;
    }

    public double getMinRisk() {
        return minRisk;
    }

    public double getMaxRisk() {
        return maxRisk;
    }

    public EventTier escalate() {
        return switch (this) {
            case BENIGN -> LOW;
            case LOW -> MEDIUM;
            case MEDIUM -> HIGH;
            case HIGH -> CRITICAL;
            case CRITICAL -> CRITICAL;  
        };
    }

    @Override
    public String toString() {
        return String.format("%s(Risk: %.2f~%.2f, 샘플링: %.0f%%)",
                name(), minRisk, maxRisk, baseSamplingRate * 100);
    }
}
