package io.contexa.contexacommon.security;


public enum TrustTier {

    
    TIER_1("Full Access"),

    
    TIER_2("Limited Sensitive Operations"),

    
    TIER_3("Read-Only"),

    
    TIER_4("Minimal Access");

    private final String description;

    TrustTier(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    
    public static TrustTier fromScore(double trustScore,
                                      io.contexa.contexacommon.properties.SecurityTrustTierProperties.ThresholdProperties thresholds) {
        if (trustScore >= thresholds.getTier1()) {
            return TIER_1;
        }
        if (trustScore >= thresholds.getTier2()) {
            return TIER_2;
        }
        if (trustScore >= thresholds.getTier3()) {
            return TIER_3;
        }
        return TIER_4;
    }

    
    public static TrustTier fromString(String tierString) {
        try {
            return TrustTier.valueOf(tierString);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid TrustTier: " + tierString, e);
        }
    }
}
