package io.contexa.contexacore.autonomous.event;

import org.springframework.context.ApplicationEvent;


public class PolicyApprovedEvent extends ApplicationEvent {

    private final String policyId;
    private final String policyName;
    private final String policyDescription;
    private final String policyRules;
    private final String approvedBy;
    private final String targetSystem;
    private final double confidenceScore;

    
    public PolicyApprovedEvent(Object source, String policyId, String policyName,
                              String policyDescription, String policyRules,
                              String approvedBy, String targetSystem, double confidenceScore) {
        super(source);
        this.policyId = policyId;
        this.policyName = policyName;
        this.policyDescription = policyDescription;
        this.policyRules = policyRules;
        this.approvedBy = approvedBy;
        this.targetSystem = targetSystem;
        this.confidenceScore = confidenceScore;
    }

    
    public String getPolicyId() {
        return policyId;
    }

    public String getPolicyName() {
        return policyName;
    }

    public String getPolicyDescription() {
        return policyDescription;
    }

    public String getPolicyRules() {
        return policyRules;
    }

    public String getApprovedBy() {
        return approvedBy;
    }

    public String getTargetSystem() {
        return targetSystem;
    }

    public double getConfidenceScore() {
        return confidenceScore;
    }

    @Override
    public String toString() {
        return String.format("PolicyApprovedEvent[id=%s, name=%s, approvedBy=%s, target=%s, confidence=%.2f]",
            policyId, policyName, approvedBy, targetSystem, confidenceScore);
    }
}