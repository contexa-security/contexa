package io.contexa.contexacore.std.pipeline.analyzer;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.enums.DiagnosisType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;


@Slf4j
public class DefaultRequestAnalyzer implements RequestAnalyzer {

    @Override
    public <T extends DomainContext> RequestCharacteristics analyze(AIRequest<T> request) {
        log.debug("[RequestAnalyzer] 요청 분석 시작: {}", request.getRequestId());

        double complexity = calculateComplexity(request);
        boolean requiresContext = shouldUseContextRetrieval(request);
        boolean fastPath = requiresFastResponse(request);
        String requestType = classifyRequestType(request);
        int dataVolume = estimateDataVolume(request);

        RequestCharacteristics characteristics = RequestCharacteristics.builder()
                .complexity(complexity)
                .requiresContextRetrieval(requiresContext)
                .requiresFastResponse(fastPath)
                .requiresHighAccuracy(!fastPath) 
                .estimatedDataVolume(dataVolume)
                .requestType(requestType)
                .metadata(extractMetadata(request))
                .build();

        log.info("[RequestAnalyzer] 분석 완료 - {}", characteristics);

        return characteristics;
    }

    
    private <T extends DomainContext> double calculateComplexity(AIRequest<T> request) {
        double complexity = 0.0;

        
        String prompt = request.getPromptTemplate();
        if (prompt != null) {
            int promptLength = prompt.length();
            complexity += Math.min(promptLength / 1000.0, 0.3);
        }

        
        T context = request.getContext();
        if (context != null) {
            
            complexity += 0.2;
        }

        
        complexity += getDiagnosisTypeComplexity(request.getDiagnosisType());

        return Math.min(complexity, 1.0);
    }

    
    private double getDiagnosisTypeComplexity(DiagnosisType type) {
        if (type == null) {
            return 0.2;
        }

        switch (type) {
            case POLICY_GENERATION:
            case ACCESS_GOVERNANCE:
            case BEHAVIORAL_ANALYSIS:
                return 0.4; 
            case RISK_ASSESSMENT:
            case RESOURCE_NAMING:
            case SECURITY_COPILOT:
            case DYNAMIC_THREAT_RESPONSE:
                return 0.3; 
            case CONDITION_TEMPLATE:
            case STUDIO_QUERY:
                return 0.2; 
            default:
                return 0.2;
        }
    }

    
    private <T extends DomainContext> boolean shouldUseContextRetrieval(AIRequest<T> request) {
        
        Boolean skipContext = request.getParameter("skipContextRetrieval", Boolean.class);
        if (skipContext != null && skipContext) {
            return false;
        }

        
        String prompt = request.getPromptTemplate();
        if (prompt != null) {
            String lowerPrompt = prompt.toLowerCase();
            if (lowerPrompt.contains("classify") ||
                    lowerPrompt.contains("simple") ||
                    lowerPrompt.contains("quick") ||
                    lowerPrompt.contains("단순") ||
                    lowerPrompt.contains("간단")) {
                return false;
            }
        }

        
        return true;
    }

    
    private <T extends DomainContext> boolean requiresFastResponse(AIRequest<T> request) {
        
        Boolean fastMode = request.getParameter("fastMode", Boolean.class);
        if (fastMode != null && fastMode) {
            return true;
        }

        
        Boolean streaming = request.getParameter("streaming", Boolean.class);
        if (streaming != null && streaming) {
            return true;
        }

        return false;
    }

    
    private <T extends DomainContext> String classifyRequestType(AIRequest<T> request) {
        String prompt = request.getPromptTemplate();
        if (prompt == null) {
            return "UNKNOWN";
        }

        String lowerPrompt = prompt.toLowerCase();
        if (lowerPrompt.contains("classify") || lowerPrompt.contains("categorize") ||
                lowerPrompt.contains("분류")) {
            return "CLASSIFICATION";
        } else if (lowerPrompt.contains("generate") || lowerPrompt.contains("create") ||
                lowerPrompt.contains("생성")) {
            return "GENERATION";
        } else if (lowerPrompt.contains("analyze") || lowerPrompt.contains("evaluate") ||
                lowerPrompt.contains("분석") || lowerPrompt.contains("평가")) {
            return "ANALYSIS";
        } else if (lowerPrompt.contains("synthesize") || lowerPrompt.contains("combine") ||
                lowerPrompt.contains("종합")) {
            return "SYNTHESIS";
        }

        return "GENERAL";
    }

    
    private <T extends DomainContext> int estimateDataVolume(AIRequest<T> request) {
        int volume = 0;

        
        if (request.getPromptTemplate() != null) {
            volume += request.getPromptTemplate().length();
        }

        
        if (request.getContext() != null) {
            volume += 500; 
        }

        return volume;
    }

    
    private <T extends DomainContext> Map<String, Object> extractMetadata(AIRequest<T> request) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("diagnosis_type", request.getDiagnosisType());
        metadata.put("request_id", request.getRequestId());
        return metadata;
    }

    @Override
    public String getAnalyzerName() {
        return "DefaultRequestAnalyzer";
    }
}
