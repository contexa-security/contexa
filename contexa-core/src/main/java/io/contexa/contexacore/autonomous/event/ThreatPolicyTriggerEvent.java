package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import org.springframework.context.ApplicationEvent;

import java.util.Map;

public class ThreatPolicyTriggerEvent extends ApplicationEvent {

    private final SecurityEvent securityEvent;
    private final String action;
    private final double riskScore;
    private final double confidence;
    private final String reasoning;
    private final String mitre;
    private final String layerName;
    private final Map<String, Object> analysisContext;

    public ThreatPolicyTriggerEvent(Object source,
                                     SecurityEvent securityEvent,
                                     String action,
                                     double riskScore,
                                     double confidence,
                                     String reasoning,
                                     String mitre,
                                     String layerName,
                                     Map<String, Object> analysisContext) {
        super(source);
        this.securityEvent = securityEvent;
        this.action = action;
        this.riskScore = riskScore;
        this.confidence = confidence;
        this.reasoning = reasoning;
        this.mitre = mitre;
        this.layerName = layerName;
        this.analysisContext = analysisContext;
    }

    public SecurityEvent getSecurityEvent() {
        return securityEvent;
    }

    public String getAction() {
        return action;
    }

    public double getRiskScore() {
        return riskScore;
    }

    public double getConfidence() {
        return confidence;
    }

    public String getReasoning() {
        return reasoning;
    }

    public String getMitre() {
        return mitre;
    }

    public String getLayerName() {
        return layerName;
    }

    public Map<String, Object> getAnalysisContext() {
        return analysisContext;
    }

    @Override
    public String toString() {
        return String.format("ThreatPolicyTriggerEvent[action=%s, layer=%s, riskScore=%.2f, confidence=%.2f]",
                action, layerName, riskScore, confidence);
    }
}
