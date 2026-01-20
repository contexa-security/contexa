package io.contexa.contexacommon.hcad.domain;

import lombok.Builder;
import lombok.Getter;


@Getter
@Builder
public class HCADAnalysisResult {

    
    private final String userId;

    
    private final double trustScore;

    
    private final String threatType;

    
    private final String threatEvidence;

    
    private final boolean isAnomaly;

    
    private final double anomalyScore;

    
    private final String action;

    
    private final double confidence;

    
    
    

    
    private final long processingTimeMs;

    
    private final HCADContext context;

    
    private final BaselineVector baseline;

    
    @Override
    public String toString() {
        return String.format(
            "HCADAnalysisResult{userId='%s', trust=%.3f, anomaly=%s, riskScore=%.3f, time=%dms}",
            userId, trustScore, isAnomaly, anomalyScore, processingTimeMs
        );
    }
}
