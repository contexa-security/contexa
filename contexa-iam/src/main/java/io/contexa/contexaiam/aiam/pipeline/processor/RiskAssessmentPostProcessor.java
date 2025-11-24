package io.contexa.contexaiam.aiam.pipeline.processor;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.processor.DomainResponseProcessor;
import io.contexa.contexacommon.domain.TrustAssessment;
import io.contexa.contexacommon.domain.response.RiskAssessmentResponse;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * RiskAssessment 도메인 응답 후처리기
 * 
 * AI가 생성한 TrustAssessment를 RiskAssessmentResponse로 래핑하고
 * 필요한 메타데이터를 추가합니다.
 */
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
        
        // RiskAssessmentResponse 생성
        RiskAssessmentResponse response = new RiskAssessmentResponse(requestId, trustAssessment);
        
        // 처리 메트릭 설정
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
        
        // AI 처리 상세 정보 설정
        String aiModel = context.getMetadata("aiModel", String.class);
        String templateKey = context.getMetadata("templateKey", String.class);
        
        Map<String, Object> aiDetails = Map.of(
            "model", aiModel != null ? aiModel : "unknown",
            "templateKey", templateKey != null ? templateKey : "riskAssessment",
            "processingMode", "structured",
            "timestamp", LocalDateTime.now().toString()
        );
        response.setAiProcessingDetails(aiDetails);
        
        log.debug("Wrapped TrustAssessment into RiskAssessmentResponse: requestId={}, trustScore={}", 
                 requestId, trustAssessment.score());
        
        return response;
    }
    
    @Override
    public int getOrder() {
        return 10; // 기본 우선순위
    }
}