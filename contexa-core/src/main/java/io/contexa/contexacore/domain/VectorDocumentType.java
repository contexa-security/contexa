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

    ANOMALY("anomaly"),

    POLICY_GENERATION("policy_generation"),

    CONDITION_TEMPLATE("condition_template"),

    RESOURCE_NAMING("resource_naming"),

    STUDIO_QUERY("studio_query"),

    STANDARD("standard"),

    BEHAVIOR_FEEDBACK("behavior_feedback"),

    BEHAVIOR_BATCH("behavior_batch"),

    RISK_ASSESSMENT_REQUEST("risk_assessment_request"),

    RISK_ASSESSMENT_RESULT("risk_assessment_result"),

    CONDITION_TEMPLATE_REQUEST("condition_template_request"),

    GENERATED_TEMPLATE("generated_template"),

    TEMPLATE_FEEDBACK("template_feedback"),

    INDIVIDUAL_TEMPLATE("individual_template"),

    CONDITION_CONTEXT("condition_context"),

    POLICY_GENERATION_REQUEST("policy_generation_request"),

    GENERATED_POLICY("generated_policy"),

    STUDIO_QUERY_RESULT("studio_query_result"),

    RESOURCE_NAMING_REQUEST("resource_naming_request"),

    RESOURCE_NAMING_RESULT("resource_naming_result"),

    RESOURCE_NAMING_FEEDBACK("resource_naming_feedback");

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
