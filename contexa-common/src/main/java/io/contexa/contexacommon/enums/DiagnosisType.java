package io.contexa.contexacommon.enums;

import lombok.Getter;


@Getter
public enum DiagnosisType {
    
    
    POLICY_GENERATION("Policy Generation", "Generate IAM policies by analyzing natural language requirements"),
    
    
    CONDITION_TEMPLATE("Condition Template Generation", "Generate general and specific condition templates using AI"),
    
    
    TRUST_ASSESSMENT("Trust Assessment", "Evaluate trust by analyzing authentication context"),
    
    
    RISK_ASSESSMENT("Risk Assessment", "Perform real-time risk assessment based on Zero Trust"),
    
    
    RESOURCE_NAMING("Resource Naming", "Convert technical identifiers to user-friendly names"),
    
    
    ROLE_RECOMMENDATION("Role Recommendation", "Recommend suitable roles for users using AI"),
    
    
    SECURITY_POSTURE("Security Posture Analysis", "Analyze overall system security posture and suggest improvements"),
    
    
    
    
    STUDIO_QUERY("Studio Natural Language Query", "Query and analyze permission structures in Authorization Studio using natural language"),
    
    
    STUDIO_RISK_ANALYSIS("Studio Risk Analysis", "Detect permission anomalies and analyze security risks in Authorization Studio"),
    
    
    STUDIO_PERMISSION_RECOMMENDATION("Studio Permission Recommendation", "Provide AI-based smart permission recommendations in Authorization Studio"),
    
    
    STUDIO_CONVERSATION("Studio Interactive Management", "Manage permissions via interactive interface in Authorization Studio"),
    
    
    SECURITY_COPILOT("Security Copilot", "Perform comprehensive security analysis through multi-Lab collaboration"),

    
    BEHAVIORAL_ANALYSIS("Behavioral Analysis", "Shift from reactive to proactive. Real-time detection and automated response to potential threats like insider threats and account takeovers to minimize damage"),

    
    ACCESS_GOVERNANCE("Access Governance Analysis", "Analyze overall health and optimization of system permission distribution to implement preventive security"),

    THREAT_RESPONSE("Threat Response", "Detect threats and respond immediately."),

    
    SOAR("SOAR", "Interactive AI-based platform for Security Orchestration, Automation, and Response"),
    
    
    DYNAMIC_THREAT_RESPONSE("Dynamic Threat Response", "Automatically generate and apply AI-based real-time threat response policies");


    private final String displayName;
    private final String description;

    DiagnosisType(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    
    public static DiagnosisType fromString(String type) {
        for (DiagnosisType diagnosisType : values()) {
            if (diagnosisType.name().equalsIgnoreCase(type) ||
                diagnosisType.displayName.equalsIgnoreCase(type)) {
                return diagnosisType;
            }
        }
        throw new IllegalArgumentException("Unknown diagnosis type: " + type);
    }
} 