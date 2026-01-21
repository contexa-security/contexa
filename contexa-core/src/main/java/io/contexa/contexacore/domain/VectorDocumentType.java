package io.contexa.contexacore.domain;

public enum VectorDocumentType {

    THREAT("threat"),

    BEHAVIOR("behavior"),

    BEHAVIOR_ANALYSIS("behavior_analysis"),

    POLICY_EVOLUTION("policy_evolution"),

    MEMORY_LTM("memory_ltm"),

    RISK_ASSESSMENT("risk_assessment"),

    ACCESS_GOVERNANCE("access_governance"),

    AUDIT("audit"),

    ACTIVITY("activity"),

    ANOMALY("anomaly");

    private final String value;

    VectorDocumentType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static VectorDocumentType fromValue(String value) {
        if (value == null) {
            return BEHAVIOR; 
        }

        for (VectorDocumentType type : values()) {
            if (type.value.equalsIgnoreCase(value)) {
                return type;
            }
        }

        return BEHAVIOR; 
    }

    @Override
    public String toString() {
        return value;
    }

    public boolean isThreatRelated() {
        return this == THREAT || this == BEHAVIOR_ANALYSIS;
    }

    public boolean isPolicyRelated() {
        return this == POLICY_EVOLUTION;
    }

    public boolean isMemoryRelated() {
        return this == MEMORY_LTM;
    }
}
