package io.contexa.contexacommon.domain;


public enum LabSpecialization {
    
    
    POLICY_GENERATION("Policy Generation & Management", 
                     "Advanced AI-driven policy creation and optimization"),
    
    
    RISK_ASSESSMENT("Risk Assessment & Analysis", 
                   "Comprehensive risk evaluation and predictive analysis"),
    
    
    USER_BEHAVIOR_ANALYSIS("User Behavior Analysis", 
                          "Deep user pattern analysis and anomaly detection"),
    
    
    ACCESS_CONTROL_OPTIMIZATION("Access Control Optimization", 
                               "Dynamic access control and zero-trust implementation"),
    
    
    AUDIT_COMPLIANCE("Audit & Compliance", 
                    "Automated audit analysis and compliance verification"),
    
    
    AI_MODEL_OPTIMIZATION("AI Model Integration & Optimization", 
                         "Advanced AI model tuning and collaborative optimization"),
    
    
    SECURITY_INTELLIGENCE("Security Intelligence", 
                         "Threat intelligence and cyber security prediction"),
    
    
    SECURITY_ANALYSIS("Security Analysis",
                     "Comprehensive security analysis and pattern recognition"),
    
    
    RECOMMENDATION_SYSTEM("Recommendation System", 
                         "Personalized security and policy recommendations"),
    
    
    WORKFLOW_AUTOMATION("Workflow Automation", 
                       "Intelligent workflow design and process optimization"),
    
    
    DATA_ANALYTICS("Data Analytics & Insights", 
                  "Advanced data analysis and predictive insights"),
    
    
    
    
    
    
    STUDIO_QUERY("Studio Natural Language Query", 
                "Authorization Studio natural language query processing and insights"),
    
    
    STUDIO_RISK_ANALYSIS("Studio Risk Analysis", 
                        "Authorization Studio risk assessment and anomaly detection"),
    
    
    STUDIO_PERMISSION_RECOMMENDATION("Studio Permission Recommendation", 
                                   "Authorization Studio smart permission recommendations"),
    
    
    STUDIO_CONVERSATION("Studio Conversational Management", 
                       "Authorization Studio conversational permission management"),

    SECURITY_RESPONSE("Studio Conversational Management",
            "Authorization Studio conversational permission management");

    private final String displayName;
    private final String description;
    
    LabSpecialization(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }
    
    
    public String getDisplayName() {
        return displayName;
    }
    
    
    public String getDescription() {
        return description;
    }
    
    
    public int getPriority() {
        return switch (this) {
            case SECURITY_INTELLIGENCE -> 1;
            case SECURITY_ANALYSIS -> 1;
            case RISK_ASSESSMENT -> 2;
            case ACCESS_CONTROL_OPTIMIZATION -> 3;
            case POLICY_GENERATION -> 4;
            case USER_BEHAVIOR_ANALYSIS -> 5;
            case AUDIT_COMPLIANCE -> 6;
            case AI_MODEL_OPTIMIZATION -> 7;
            case RECOMMENDATION_SYSTEM -> 8;
            case WORKFLOW_AUTOMATION -> 9;
            case DATA_ANALYTICS -> 10;
            case SECURITY_RESPONSE -> 11;
            
            case STUDIO_QUERY -> 3;
            case STUDIO_RISK_ANALYSIS -> 2;
            case STUDIO_PERMISSION_RECOMMENDATION -> 4;
            case STUDIO_CONVERSATION -> 5;
        };
    }
}