package io.contexa.contexaiam.aiam.pipeline.processor;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.processor.DomainResponseProcessor;
import io.contexa.contexacommon.domain.TrustAssessment;
import io.contexa.contexacommon.domain.response.RiskAssessmentResponse;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.Map;

@Slf4j
public class RiskAssessmentPostProcessor implements DomainResponseProcessor {
    
    @Override
    public boolean supports(String templateKey) {
        return "riskAssessment".equals(templateKey) || 
               "zeroTrustAssessment".equals(templateKey) ||
               "securityRiskAnalysis".equals(templateKey);
    }
    
    @Override
    public boolean supportsType(Class<?> responseType) {
        return TrustAssessment.class.isAssignableFrom(responseType);
    }
    
    @Override
    public Object wrapResponse(Object parsedData, PipelineExecutionContext context) {
        if (!(parsedData instanceof TrustAssessment trustAssessment)) {
            throw new IllegalArgumentException(
                "Expected TrustAssessment but got: " + 
                (parsedData != null ? parsedData.getClass() : "null")
            );
        }

        String requestId = context.getExecutionId();

        RiskAssessmentResponse response = new RiskAssessmentResponse(requestId, trustAssessment);

        Long startTime = context.getMetadata("startTime", Long.class);
        if (startTime != null) {
            long processingTime = System.currentTimeMillis() - startTime;
            
            Boolean usedHistory = context.getMetadata("usedHistoryAnalysis", Boolean.class);
            Boolean usedBehavior = context.getMetadata("usedBehaviorAnalysis", Boolean.class);
            Integer historyRecords = context.getMetadata("analyzedHistoryRecords", Integer.class);
            String nodeId = context.getMetadata("nodeId", String.class);
            
            response.setProcessingMetrics(
                processingTime,
                nodeId != null ? nodeId : "default-node",
                usedHistory != null ? usedHistory : false,
                usedBehavior != null ? usedBehavior : false,
                historyRecords != null ? historyRecords : 0
            );
        }

        String aiModel = context.getMetadata("aiModel", String.class);
        String templateKey = context.getMetadata("templateKey", String.class);
        
        Map<String, Object> aiDetails = Map.of(
            "model", aiModel != null ? aiModel : "unknown",
            "templateKey", templateKey != null ? templateKey : "riskAssessment",
            "processingMode", "structured",
            "timestamp", LocalDateTime.now().toString()
        );
        response.setAiProcessingDetails(aiDetails);

        return response;
    }
    
    @Override
    public int getOrder() {
        return 10; 
    }
}