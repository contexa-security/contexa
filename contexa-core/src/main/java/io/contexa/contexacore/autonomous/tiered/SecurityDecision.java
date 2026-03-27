package io.contexa.contexacore.autonomous.tiered;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityDecision {

    /**
     * Primary semantic judgment proposed by the LLM.
     */
    private ZeroTrustAction action;
    private Double riskScore;
    /**
     * Effective confidence after autonomy constraints are applied.
     */
    private Double confidence;
    private Double llmAuditRiskScore;
    /**
     * Raw confidence emitted by the LLM before autonomy constraints.
     */
    private Double llmAuditConfidence;
    private long analysisTime;                
    private long processingTimeMs;            
    private int processingLayer;              

    private String llmModel;                  

    private Map<String, Object> sessionContext;    
    private List<String> behaviorPatterns;        
    private String threatCategory;                 
    private List<String> mitigationActions;       
    private String reasoning;                      

    private List<String> iocIndicators;            
    private Map<String, String> mitreMapping;      
    private String soarPlaybook;                   
    private boolean requiresApproval;              
    private String expertRecommendation;           
    private String eventId;
    /**
     * Final action used for autonomous execution.
     * When null, the proposed action is also the enforced action.
     */
    private ZeroTrustAction autonomousAction;
    private Boolean autonomyConstraintApplied;
    @Builder.Default
    private List<String> autonomyConstraintReasons = new ArrayList<>();
    private String autonomyConstraintSummary;

    public Double resolveAuditRiskScore() {
        return llmAuditRiskScore;
    }

    public Double resolveAuditConfidence() {
        return llmAuditConfidence;
    }

    public ZeroTrustAction resolveAutonomousAction() {
        return autonomousAction != null ? autonomousAction : action;
    }

}
