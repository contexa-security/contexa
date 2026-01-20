package io.contexa.contexacore.autonomous.strategy;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityContext;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;


@Slf4j
@RequiredArgsConstructor
public class VectorStoreEvaluationStrategy implements ThreatEvaluationStrategy {

    @Autowired(required = false)
    private UnifiedVectorService unifiedVectorService;
    
    private static final String STRATEGY_NAME = "VECTOR_STORE";
    
    private static final double DEFAULT_SIMILARITY_THRESHOLD = 0.0;
    private static final int DEFAULT_TOP_K = 10;
    
    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        try {
            log.debug("[VectorStoreEvaluationStrategy][AI Native] Vector Store threat evaluation for event: {}", event.getEventId());

            if (unifiedVectorService == null) {
                log.warn("[VectorStoreEvaluationStrategy][AI Native] UnifiedVectorService not available");
                return createFallbackAssessment(event);
            }

            
            String queryText = buildQueryFromEvent(event);

            
            List<Document> similarPatterns = searchSimilarPatterns(queryText);

            
            List<ThreatIndicator> indicators = extractIndicatorsFromPatterns(similarPatterns, event);

            
            

            return ThreatAssessment.builder()
                .eventId(event.getEventId())
                .assessmentId(UUID.randomUUID().toString())
                .assessedAt(LocalDateTime.now())
                .evaluator(getStrategyName())
                .riskScore(Double.NaN)  
                .indicators(convertToStringList(indicators))
                .recommendedActions(List.of("LLM_ANALYSIS_REQUIRED"))  
                .confidence(Double.NaN)  
                
                .action("ESCALATE")  
                .build();

        } catch (Exception e) {
            log.error("[VectorStoreEvaluationStrategy][AI Native] Error for event: {}", event.getEventId(), e);
            return createErrorAssessment(event, e);
        }
    }
    
    @Override
    public ThreatAssessment evaluateWithContext(SecurityEvent event, SecurityContext context) {
        log.debug("[VectorStoreEvaluationStrategy][AI Native] Context-aware evaluation for event: {}", event.getEventId());

        
        
        return evaluate(event);
    }
    
    @Override
    public List<ThreatIndicator> extractIndicators(SecurityEvent event) {
        try {
            if (event == null) {
                log.warn("SecurityEvent가 null입니다. 지표 추출을 건너뜁니다.");
                return new ArrayList<>();
            }
            
            if (unifiedVectorService == null) {
                log.warn("UnifiedVectorService가 null입니다. 지표 추출을 건너뜁니다.");
                return new ArrayList<>();
            }
            
            String queryText = buildQueryFromEvent(event);
            List<Document> patterns = searchSimilarPatterns(queryText);
            return extractIndicatorsFromPatterns(patterns, event);
            
        } catch (Exception e) {
            log.error("지표 추출 중 오류 발생", e);
            return new ArrayList<>();
        }
    }
    
    @Override
    public String getStrategyName() {
        return STRATEGY_NAME;
    }
    
    @Override
    public String getDescription() {
        return "Vector Store pattern-based threat evaluation using machine learning similarity search";
    }
    
    
    public Map<String, String> mapToFramework(SecurityEvent event) {
        Map<String, String> mapping = new HashMap<>();
        mapping.put("FRAMEWORK", "VECTOR_PATTERN_MATCHING");
        mapping.put("METHOD", "SIMILARITY_SEARCH");
        
        mapping.put("SEVERITY", event.getSeverity() != null ? event.getSeverity().toString() : "INFO");
        mapping.put("ALGORITHM", "COSINE_SIMILARITY");
        return mapping;
    }
    
    
    @Override
    public List<String> getRecommendedActions(SecurityEvent event) {
        
        
        return List.of("LLM_ANALYSIS_REQUIRED");
    }
    
    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        
        
        return Double.NaN;
    }
    
    
    @Override
    public boolean canEvaluate(SecurityEvent.Severity severity) {
        
        return unifiedVectorService != null;
    }
    
    @Override
    public int getPriority() {
        return 80; 
    }
    
    
    
    private String buildQueryFromEvent(SecurityEvent event) {
        StringBuilder query = new StringBuilder();
        
        
        query.append("severity:").append(event.getSeverity() != null ? event.getSeverity() : "INFO");
        
        if (event.getSourceIp() != null) {
            query.append(" source_ip:").append(event.getSourceIp());
        }
        
        
        Object targetResource = event.getMetadata() != null ? event.getMetadata().get("targetResource") : null;
        if (targetResource != null) {
            query.append(" target:").append(targetResource);
        }
        
        if (event.getSeverity() != null) {
            query.append(" severity:").append(event.getSeverity());
        }
        
        if (event.getUserId() != null) {
            query.append(" user:").append(event.getUserId());
        }
        
        return query.toString();
    }
    
    private String buildContextQuery(SecurityEvent event, SecurityContext context) {
        StringBuilder query = new StringBuilder();
        query.append(buildQueryFromEvent(event));

        if (context.getUserId() != null) {
            query.append(" context_user:").append(context.getUserId());
        }

        
        
        if (context.getTrustScore() != null) {
            query.append(" trust_score:").append(context.getTrustScore());
        }

        return query.toString();
    }
    
    private List<Document> searchSimilarPatterns(String query) {
        try {
            SearchRequest searchRequest = SearchRequest.builder()
                .query(query)
                .topK(DEFAULT_TOP_K)
                .similarityThreshold(DEFAULT_SIMILARITY_THRESHOLD)
                .build();
                
            return unifiedVectorService.searchSimilar(searchRequest);
        } catch (Exception e) {
            log.error("Error searching similar patterns", e);
            return new ArrayList<>();
        }
    }
    
    private List<Document> searchContextPatterns(String contextQuery) {
        try {
            SearchRequest searchRequest = SearchRequest.builder()
                .query(contextQuery)
                .topK(5)
                
                .similarityThreshold(0.0)
                .build();

            return unifiedVectorService.searchSimilar(searchRequest);
        } catch (Exception e) {
            log.error("[VectorStoreEvaluationStrategy][AI Native] Error searching context patterns", e);
            return new ArrayList<>();
        }
    }
    
    private List<ThreatIndicator> extractIndicatorsFromPatterns(List<Document> patterns, SecurityEvent event) {
        List<ThreatIndicator> indicators = new ArrayList<>();
        
        for (Document pattern : patterns) {
            try {
                Map<String, Object> metadata = pattern.getMetadata();
                
                ThreatIndicator indicator = new ThreatIndicator();
                indicator.setIndicatorId(UUID.randomUUID().toString());
                indicator.setType(extractIndicatorType(metadata));
                indicator.setValue(extractIndicatorValue(metadata, pattern));
                indicator.setSeverity(extractSeverity(metadata));
                indicator.setConfidence(extractConfidenceScore(metadata));
                indicator.setDescription(createIndicatorDescription(metadata, pattern));
                indicator.setDetectedAt(LocalDateTime.now());
                indicator.setSource("VectorStore");
                
                indicators.add(indicator);
                
            } catch (Exception e) {
                log.warn("Error creating indicator from pattern", e);
            }
        }
        
        return indicators;
    }
    
    private ThreatIndicator.IndicatorType extractIndicatorType(Map<String, Object> metadata) {
        Object type = metadata.get("threat_type");
        if (type != null) {
            try {
                return ThreatIndicator.IndicatorType.valueOf(type.toString().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ThreatIndicator.IndicatorType.PATTERN;
            }
        }
        return ThreatIndicator.IndicatorType.PATTERN;
    }
    
    private String extractIndicatorValue(Map<String, Object> metadata, Document pattern) {
        Object similarity = metadata.get("similarity");
        if (similarity != null) {
            return "similarity:" + similarity;
        }
        return "pattern_content:" + pattern.getText().substring(0, Math.min(100, pattern.getText().length()));
    }
    
    private ThreatIndicator.Severity extractSeverity(Map<String, Object> metadata) {
        Object severity = metadata.get("severity");
        if (severity != null) {
            try {
                return ThreatIndicator.Severity.valueOf(severity.toString().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ThreatIndicator.Severity.MEDIUM;
            }
        }
        return ThreatIndicator.Severity.MEDIUM;
    }
    
    private Double extractConfidenceScore(Map<String, Object> metadata) {
        Object confidence = metadata.get("confidence");
        if (confidence instanceof Number) {
            return ((Number) confidence).doubleValue();
        }
        
        return Double.NaN;
    }
    
    private String createIndicatorDescription(Map<String, Object> metadata, Document pattern) {
        return String.format("Similar pattern found with metadata: %s", 
            metadata.entrySet().stream()
                .limit(3)
                .map(e -> e.getKey() + ":" + e.getValue())
                .collect(Collectors.joining(", ")));
    }
    
    
    

    
    
    

    
    

    
    
    
    
    
    
    private Map<String, Object> createMetadata(SecurityEvent event, List<Document> patterns) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("strategy", getStrategyName());
        metadata.put("pattern_count", patterns.size());
        
        metadata.put("severity", event.getSeverity() != null ? event.getSeverity().toString() : "INFO");
        metadata.put("evaluation_time", LocalDateTime.now().toString());
        
        if (!patterns.isEmpty()) {
            metadata.put("top_similarity", patterns.get(0).getMetadata().get("similarity"));
        }
        
        return metadata;
    }
    
    private Map<String, Object> createContextMetadata(SecurityEvent event, SecurityContext context, 
                                                    List<Document> contextPatterns, ThreatAssessment basicAssessment) {
        Map<String, Object> metadata = createMetadata(event, contextPatterns);
        metadata.put("context_enabled", true);
        metadata.put("trust_score", context.getTrustScore());
        metadata.put("context_patterns", contextPatterns.size());
        metadata.put("basic_risk_score", basicAssessment.getRiskScore());
        return metadata;
    }
    
    private List<String> convertToStringList(List<ThreatIndicator> indicators) {
        return indicators.stream()
            .map(indicator -> indicator.getType() + ":" + indicator.getValue())
            .collect(Collectors.toList());
    }
    
    private ThreatAssessment createFallbackAssessment(SecurityEvent event) {
        
        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator(getStrategyName() + "-Fallback")
            .riskScore(Double.NaN)  
            .indicators(List.of("VECTORSTORE_UNAVAILABLE"))
            .recommendedActions(List.of("LLM_ANALYSIS_REQUIRED"))
            .confidence(Double.NaN)  
            
            .action("ESCALATE")  
            .build();
    }

    private ThreatAssessment createErrorAssessment(SecurityEvent event, Exception error) {
        
        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator(getStrategyName() + "-Error")
            .riskScore(Double.NaN)  
            .indicators(List.of("EVALUATION_ERROR"))
            .recommendedActions(List.of("LLM_ANALYSIS_REQUIRED", "MANUAL_REVIEW"))
            .confidence(Double.NaN)  
            
            .action("ESCALATE")  
            .build();
    }
}