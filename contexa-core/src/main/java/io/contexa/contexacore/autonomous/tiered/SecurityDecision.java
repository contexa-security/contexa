package io.contexa.contexacore.autonomous.tiered;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityDecision {

    public enum Action {
        ALLOW,           
        BLOCK,           
        CHALLENGE,       
        ESCALATE         
    }

    private Action action;                    
    private double riskScore;                 
    private double confidence;                
    private long analysisTime;                
    private long processingTimeMs;            
    private int processingLayer;              

    private String llmModel;                  

    private Map<String, Object> sessionContext;    
    private List<String> behaviorPatterns;        
    private String threatCategory;                 
    private List<String> mitigationActions;       
    private String reasoning;                      

    private String attackScenario;                 
    private List<String> iocIndicators;            
    private Map<String, String> mitreMapping;      
    private String soarPlaybook;                   
    private boolean requiresApproval;              
    private String expertRecommendation;           

    private String eventId;                        
    private String analysisId;                     
    private Map<String, Object> metadata;          

    public boolean shouldBlock() {
        
        if (action == null) {
            return true;
        }
        
        return action == Action.BLOCK;
    }

    public boolean shouldEscalate() {
        return action == Action.ESCALATE;
    }

    public boolean isConfident() {

        return !Double.isNaN(confidence);
    }

    public void calculateProcessingTime() {
        if (analysisTime > 0) {
            this.processingTimeMs = System.currentTimeMillis() - analysisTime;
        }
    }

    public static SecurityDecision allow(double riskScore) {
        return SecurityDecision.builder()
                .action(Action.ALLOW)
                .riskScore(riskScore)
                .confidence(Double.NaN)
                .analysisTime(System.currentTimeMillis())
                .build();
    }

    public static SecurityDecision block(double riskScore) {
        return SecurityDecision.builder()
                .action(Action.BLOCK)
                .riskScore(riskScore)
                .confidence(Double.NaN)
                .analysisTime(System.currentTimeMillis())
                .build();
    }

    public static SecurityDecision escalate(double riskScore) {
        return SecurityDecision.builder()
                .action(Action.ESCALATE)
                .riskScore(riskScore)
                .confidence(Double.NaN)
                .analysisTime(System.currentTimeMillis())
                .build();
    }
}