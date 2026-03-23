package io.contexa.contexacore.autonomous.tiered;

import io.contexa.contexacommon.enums.ZeroTrustAction;
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

    private ZeroTrustAction action;
    private Double riskScore;
    private Double confidence;
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

    private List<String> evidence;
    private String legitimateHypothesis;
    private String suspiciousHypothesis;

}
