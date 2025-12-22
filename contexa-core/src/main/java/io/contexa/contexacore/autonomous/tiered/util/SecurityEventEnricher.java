package io.contexa.contexacore.autonomous.tiered.util;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * SecurityEvent 메타데이터 보강 유틸리티
 * 
 * SecurityEvent의 metadata Map을 통해 추가 필드를 관리하는 헬퍼 클래스입니다.
 * Layer 전략들이 필요로 하는 추가 필드를 안전하게 처리합니다.
 */
public class SecurityEventEnricher {
    
    // 메타데이터 키 상수
    public static final String TARGET_RESOURCE = "targetResource";
    public static final String HTTP_METHOD = "httpMethod";
    public static final String REQUEST_PAYLOAD = "requestPayload";
    public static final String USER_BEHAVIOR = "userBehavior";
    public static final String PATTERN_SCORE = "patternScore";
    public static final String RISK_INDICATORS = "riskIndicators";
    public static final String CONTEXT_EMBEDDINGS = "contextEmbeddings";
    public static final String LAYER_DECISIONS = "layerDecisions";
    public static final String PROCESSING_TIMESTAMP = "processingTimestamp";
    public static final String CORRELATION_ID = "correlationId";
    
    /**
     * SecurityEvent에 메타데이터 추가
     */
    public void enrichEvent(SecurityEvent event, String key, Object value) {
        if (event.getMetadata() == null) {
            event.setMetadata(new HashMap<>());
        }
        event.getMetadata().put(key, value);
    }
    
    /**
     * 대상 리소스 설정
     */
    public void setTargetResource(SecurityEvent event, String targetResource) {
        enrichEvent(event, TARGET_RESOURCE, targetResource);
    }
    
    /**
     * 대상 리소스 조회
     */
    public Optional<String> getTargetResource(SecurityEvent event) {
        return getMetadataValue(event, TARGET_RESOURCE, String.class);
    }
    
    /**
     * HTTP 메서드 설정
     */
    public void setHttpMethod(SecurityEvent event, String method) {
        enrichEvent(event, HTTP_METHOD, method);
    }
    
    /**
     * HTTP 메서드 조회
     */
    public Optional<String> getHttpMethod(SecurityEvent event) {
        return getMetadataValue(event, HTTP_METHOD, String.class);
    }
    
    /**
     * 요청 페이로드 설정
     */
    public void setRequestPayload(SecurityEvent event, Object payload) {
        enrichEvent(event, REQUEST_PAYLOAD, payload);
    }
    
    /**
     * 요청 페이로드 조회
     */
    public Optional<Object> getRequestPayload(SecurityEvent event) {
        return getMetadataValue(event, REQUEST_PAYLOAD, Object.class);
    }
    
    /**
     * 사용자 행동 패턴 설정
     */
    public void setUserBehavior(SecurityEvent event, Map<String, Object> behavior) {
        enrichEvent(event, USER_BEHAVIOR, behavior);
    }
    
    /**
     * 사용자 행동 패턴 조회
     */
    @SuppressWarnings("unchecked")
    public Optional<Map<String, Object>> getUserBehavior(SecurityEvent event) {
        if (event.getMetadata() == null || !event.getMetadata().containsKey(USER_BEHAVIOR)) {
            return Optional.empty();
        }
        Object value = event.getMetadata().get(USER_BEHAVIOR);
        if (value instanceof Map) {
            return Optional.of((Map<String, Object>) value);
        }
        return Optional.empty();
    }
    
    /**
     * 패턴 점수 설정
     */
    public void setPatternScore(SecurityEvent event, Double score) {
        enrichEvent(event, PATTERN_SCORE, score);
    }
    
    /**
     * 패턴 점수 조회
     */
    public Optional<Double> getPatternScore(SecurityEvent event) {
        return getMetadataValue(event, PATTERN_SCORE, Double.class);
    }
    
    /**
     * 위험 지표 설정
     */
    public void setRiskIndicators(SecurityEvent event, Map<String, Object> indicators) {
        enrichEvent(event, RISK_INDICATORS, indicators);
    }
    
    /**
     * 위험 지표 조회
     */
    @SuppressWarnings("unchecked")
    public Optional<Map<String, Object>> getRiskIndicators(SecurityEvent event) {
        if (event.getMetadata() == null || !event.getMetadata().containsKey(RISK_INDICATORS)) {
            return Optional.empty();
        }
        Object value = event.getMetadata().get(RISK_INDICATORS);
        if (value instanceof Map) {
            return Optional.of((Map<String, Object>) value);
        }
        return Optional.empty();
    }
    
    /**
     * 컨텍스트 임베딩 설정
     */
    public void setContextEmbeddings(SecurityEvent event, float[] embeddings) {
        enrichEvent(event, CONTEXT_EMBEDDINGS, embeddings);
    }
    
    /**
     * 컨텍스트 임베딩 조회
     */
    public Optional<float[]> getContextEmbeddings(SecurityEvent event) {
        return getMetadataValue(event, CONTEXT_EMBEDDINGS, float[].class);
    }
    
    /**
     * Layer 결정 사항 추가
     */
    @SuppressWarnings("unchecked")
    public void addLayerDecision(SecurityEvent event, String layer, Map<String, Object> decision) {
        Map<String, Object> decisions = (Map<String, Object>) event.getMetadata()
            .computeIfAbsent(LAYER_DECISIONS, k -> new HashMap<String, Object>());
        decisions.put(layer, decision);
    }
    
    /**
     * Layer 결정 사항 조회
     */
    @SuppressWarnings("unchecked")
    public Optional<Map<String, Object>> getLayerDecisions(SecurityEvent event) {
        if (event.getMetadata() == null || !event.getMetadata().containsKey(LAYER_DECISIONS)) {
            return Optional.empty();
        }
        Object value = event.getMetadata().get(LAYER_DECISIONS);
        if (value instanceof Map) {
            return Optional.of((Map<String, Object>) value);
        }
        return Optional.empty();
    }
    
    /**
     * 상관 ID 설정
     */
    public void setCorrelationId(SecurityEvent event, String correlationId) {
        enrichEvent(event, CORRELATION_ID, correlationId);
    }
    
    /**
     * 상관 ID 조회
     */
    public Optional<String> getCorrelationId(SecurityEvent event) {
        return getMetadataValue(event, CORRELATION_ID, String.class);
    }
    
    /**
     * 메타데이터 값 안전하게 조회
     */
    @SuppressWarnings("unchecked")
    private <T> Optional<T> getMetadataValue(SecurityEvent event, String key, Class<T> type) {
        if (event.getMetadata() == null || !event.getMetadata().containsKey(key)) {
            return Optional.empty();
        }
        
        Object value = event.getMetadata().get(key);
        if (value == null) {
            return Optional.empty();
        }
        
        if (type.isInstance(value)) {
            return Optional.of((T) value);
        }
        
        return Optional.empty();
    }
    
    /**
     * 이벤트가 특정 메타데이터를 포함하는지 확인
     */
    public boolean hasMetadata(SecurityEvent event, String key) {
        return event.getMetadata() != null && event.getMetadata().containsKey(key);
    }
    
    /**
     * 이벤트 컨텍스트 생성
     */
    public Map<String, Object> createEventContext(SecurityEvent event) {
        Map<String, Object> context = new HashMap<>();
        
        // 기본 정보
        context.put("eventId", event.getEventId());
        context.put("eventType", event.getEventType());
        context.put("severity", event.getSeverity());
        context.put("timestamp", event.getTimestamp());
        
        // 네트워크 정보
        if (event.getSourceIp() != null) {
            context.put("sourceIp", event.getSourceIp());
        }
        if (event.getTargetIp() != null) {
            context.put("targetIp", event.getTargetIp());
        }
        
        // 사용자 정보
        if (event.getUserId() != null) {
            context.put("userId", event.getUserId());
        }
        if (event.getSessionId() != null) {
            context.put("sessionId", event.getSessionId());
        }
        
        // AI Native: deprecated 필드(threatType, confidenceScore) 제거
        // ThreatAssessment 또는 SecurityDecision에서 관리
        
        // 메타데이터에서 추가 정보
        getTargetResource(event).ifPresent(resource -> context.put("targetResource", resource));
        getHttpMethod(event).ifPresent(method -> context.put("httpMethod", method));
        getPatternScore(event).ifPresent(score -> context.put("patternScore", score));
        
        return context;
    }
    
    /**
     * 위험 점수 계산 (메타데이터 기반)
     */
    public double calculateRiskScore(SecurityEvent event) {
        double baseScore = 0.0;
        
        // 심각도 기반 점수
        if (event.getSeverity() != null) {
            baseScore = event.getSeverity().getScore() / 10.0; // 0.1 ~ 1.0
        }
        
        // AI Native: deprecated getConfidenceScore() 제거
        // 신뢰도는 LLM 분석 결과(SecurityDecision.confidence)에서 결정
        
        // 패턴 점수 가중
        getPatternScore(event).ifPresent(score -> {
            // 패턴 점수가 있으면 평균 계산
        });
        
        // 위험 지표 가중
        getRiskIndicators(event).ifPresent(indicators -> {
            // 추가 위험 지표 반영
        });
        
        return Math.min(1.0, Math.max(0.0, baseScore)); // 0.0 ~ 1.0 범위
    }
    
    /**
     * 이벤트 요약 생성
     */
    public String generateEventSummary(SecurityEvent event) {
        StringBuilder summary = new StringBuilder();
        summary.append("Event[").append(event.getEventId()).append("]: ");
        summary.append(event.getEventType()).append(" ");
        summary.append("(").append(event.getSeverity()).append(") ");
        
        if (event.getUserId() != null) {
            summary.append("User:").append(event.getUserId()).append(" ");
        }
        
        if (event.getSourceIp() != null) {
            summary.append("From:").append(event.getSourceIp()).append(" ");
        }
        
        getTargetResource(event).ifPresent(resource -> 
            summary.append("Target:").append(resource).append(" ")
        );
        
        getHttpMethod(event).ifPresent(method -> 
            summary.append("Method:").append(method).append(" ")
        );
        
        return summary.toString().trim();
    }
}