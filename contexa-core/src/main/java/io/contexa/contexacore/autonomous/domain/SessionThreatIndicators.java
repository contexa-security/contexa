package io.contexa.contexacore.autonomous.domain;

import lombok.Data;
import java.util.HashMap;
import java.util.Map;


@Data
public class SessionThreatIndicators {
    
    private boolean ipChanged = false;
    private boolean userAgentChanged = false;
    private boolean suspiciousActivity = false;
    private double additionalRisk = 0.0;
    private Map<String, String> indicators = new HashMap<>();
    
    
    public boolean isSessionHijackSuspected() {
        return ipChanged || userAgentChanged || suspiciousActivity || additionalRisk > 0.5;
    }
    
    
    public boolean shouldInvalidateSession() {
        
        return (ipChanged && userAgentChanged) || additionalRisk > 0.7;
    }
    
    
    public void addRisk(double risk) {
        this.additionalRisk = Math.min(1.0, this.additionalRisk + risk);
    }
    
    
    public void addIndicator(String key, String value) {
        this.indicators.put(key, value);
    }
    
    
    public void addIndicator(String key, double score, String description) {
        this.indicators.put(key, description);
        this.additionalRisk = Math.min(1.0, this.additionalRisk + score);
    }
    
    
    public void incrementScore(double score) {
        this.additionalRisk = Math.min(1.0, this.additionalRisk + score);
    }
    
    @Override
    public String toString() {
        return String.format("SessionThreatIndicators{ipChanged=%s, uaChanged=%s, suspicious=%s, risk=%.2f, indicators=%s}",
                ipChanged, userAgentChanged, suspiciousActivity, additionalRisk, indicators);
    }
}