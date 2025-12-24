package io.contexa.contexacore.autonomous.tiered.util;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import lombok.extern.slf4j.Slf4j;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * SecurityEvent 메타데이터 보강 유틸리티
 *
 * SecurityEvent의 metadata Map을 통해 추가 필드를 관리하는 헬퍼 클래스입니다.
 * Layer 전략들이 필요로 하는 추가 필드를 안전하게 처리합니다.
 */
@Slf4j
public class SecurityEventEnricher {

    // Base64 패턴 감지 정규식
    private static final Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9+/=]{4,}$");
    // URL 인코딩 패턴 감지 (%XX 형식)
    private static final Pattern URL_ENCODED_PATTERN = Pattern.compile(".*%[0-9A-Fa-f]{2}.*");
    
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
     * 디코딩된 페이로드 조회 (Phase 3-7: Payload 인코딩 전처리)
     *
     * Base64 또는 URL 인코딩된 페이로드를 자동 감지하여 디코딩합니다.
     * LLM이 인코딩된 데이터를 직접 분석하지 않도록 전처리합니다.
     *
     * 디코딩 순서:
     * 1. URL 인코딩 감지 및 디코딩 (%XX 형식)
     * 2. Base64 인코딩 감지 및 디코딩
     * 3. 디코딩 실패 시 원본 반환
     *
     * @param event SecurityEvent
     * @return 디코딩된 페이로드 문자열 (Optional)
     */
    public Optional<String> getDecodedPayload(SecurityEvent event) {
        return getRequestPayload(event)
                .map(payload -> {
                    String payloadStr = payload.toString();
                    return decodePayload(payloadStr);
                });
    }

    /**
     * 페이로드 디코딩 (URL + Base64)
     *
     * @param payload 원본 페이로드
     * @return 디코딩된 페이로드 (디코딩 불가 시 원본 반환)
     */
    private String decodePayload(String payload) {
        if (payload == null || payload.isEmpty()) {
            return payload;
        }

        String decoded = payload;

        // 1. URL 디코딩 시도
        if (URL_ENCODED_PATTERN.matcher(payload).matches()) {
            try {
                decoded = URLDecoder.decode(payload, StandardCharsets.UTF_8);
                log.debug("[SecurityEventEnricher] URL decoded payload: {} -> {}",
                        truncateForLog(payload), truncateForLog(decoded));
            } catch (Exception e) {
                log.debug("[SecurityEventEnricher] URL decoding failed, keeping original");
            }
        }

        // 2. Base64 디코딩 시도 (URL 디코딩 후)
        if (isLikelyBase64(decoded)) {
            try {
                byte[] decodedBytes = Base64.getDecoder().decode(decoded);
                String base64Decoded = new String(decodedBytes, StandardCharsets.UTF_8);
                // 디코딩 결과가 출력 가능한 문자열인지 확인
                if (isPrintable(base64Decoded)) {
                    log.debug("[SecurityEventEnricher] Base64 decoded payload: {} -> {}",
                            truncateForLog(decoded), truncateForLog(base64Decoded));
                    decoded = base64Decoded;
                }
            } catch (Exception e) {
                log.debug("[SecurityEventEnricher] Base64 decoding failed, keeping previous result");
            }
        }

        return decoded;
    }

    /**
     * Base64 인코딩 여부 추정
     * - 길이가 4의 배수
     * - Base64 문자셋만 포함
     * - 최소 길이 이상
     */
    private boolean isLikelyBase64(String str) {
        if (str == null || str.length() < 8) {
            return false;
        }
        // 길이가 4의 배수이고 Base64 패턴에 맞는지 확인
        return str.length() % 4 == 0 && BASE64_PATTERN.matcher(str).matches();
    }

    /**
     * 문자열이 출력 가능한지 확인 (바이너리 데이터 필터링)
     */
    private boolean isPrintable(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        // 80% 이상이 출력 가능한 ASCII 문자인지 확인
        long printableCount = str.chars()
                .filter(c -> c >= 32 && c < 127)
                .count();
        return (double) printableCount / str.length() >= 0.8;
    }

    /**
     * 로깅용 문자열 잘라내기
     */
    private String truncateForLog(String str) {
        if (str == null) return "null";
        if (str.length() <= 50) return str;
        return str.substring(0, 47) + "...";
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
     * 메타데이터 값 안전하게 조회 (Phase 3-8: 타입 안전성 강화)
     *
     * 타입 변환 지원:
     * - 정확한 타입 일치
     * - 숫자 타입 자동 변환 (Integer -> Long, Float -> Double 등)
     * - 문자열 -> 숫자 변환
     * - 타입 불일치 시 경고 로깅
     *
     * @param event SecurityEvent
     * @param key 메타데이터 키
     * @param type 요청 타입
     * @return Optional<T> 변환된 값
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

        // 1. 정확한 타입 일치
        if (type.isInstance(value)) {
            return Optional.of((T) value);
        }

        // 2. 숫자 타입 변환 시도
        if (Number.class.isAssignableFrom(type) && value instanceof Number) {
            try {
                Number numValue = (Number) value;
                Object converted = convertNumber(numValue, type);
                if (converted != null) {
                    return Optional.of((T) converted);
                }
            } catch (Exception e) {
                log.debug("[SecurityEventEnricher] Number conversion failed for key '{}': {} -> {}",
                        key, value.getClass().getSimpleName(), type.getSimpleName());
            }
        }

        // 3. 문자열 -> 숫자 변환 시도
        if (Number.class.isAssignableFrom(type) && value instanceof String) {
            try {
                Object converted = parseStringToNumber((String) value, type);
                if (converted != null) {
                    return Optional.of((T) converted);
                }
            } catch (Exception e) {
                log.debug("[SecurityEventEnricher] String to number parsing failed for key '{}': '{}'",
                        key, value);
            }
        }

        // 4. 문자열 요청 시 toString() 사용
        if (type == String.class) {
            return Optional.of((T) value.toString());
        }

        // 5. 타입 불일치 경고 로깅
        log.warn("[SecurityEventEnricher] Type mismatch for key '{}': expected {}, got {}",
                key, type.getSimpleName(), value.getClass().getSimpleName());
        return Optional.empty();
    }

    /**
     * Number 타입 변환
     */
    private Object convertNumber(Number value, Class<?> targetType) {
        if (targetType == Integer.class || targetType == int.class) {
            return value.intValue();
        } else if (targetType == Long.class || targetType == long.class) {
            return value.longValue();
        } else if (targetType == Double.class || targetType == double.class) {
            return value.doubleValue();
        } else if (targetType == Float.class || targetType == float.class) {
            return value.floatValue();
        } else if (targetType == Short.class || targetType == short.class) {
            return value.shortValue();
        } else if (targetType == Byte.class || targetType == byte.class) {
            return value.byteValue();
        }
        return null;
    }

    /**
     * 문자열 -> Number 파싱
     */
    private Object parseStringToNumber(String value, Class<?> targetType) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }
        String trimmed = value.trim();
        if (targetType == Integer.class || targetType == int.class) {
            return Integer.parseInt(trimmed);
        } else if (targetType == Long.class || targetType == long.class) {
            return Long.parseLong(trimmed);
        } else if (targetType == Double.class || targetType == double.class) {
            return Double.parseDouble(trimmed);
        } else if (targetType == Float.class || targetType == float.class) {
            return Float.parseFloat(trimmed);
        }
        return null;
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
     *
     * @deprecated AI Native 원칙 위반 - 플랫폼이 직접 점수를 계산하면 안 됩니다.
     *             위험 점수(riskScore)는 LLM이 SecurityDecision에서 결정해야 합니다.
     *             대신 SecurityDecision.getRiskScore()를 사용하세요.
     *
     *             Phase 13 AI Native 원칙:
     *             - 플랫폼: raw 데이터만 제공
     *             - LLM: action(ALLOW/BLOCK/CHALLENGE/ESCALATE) 및 riskScore 결정
     *
     * @see io.contexa.contexacore.autonomous.domain.SecurityDecision#getRiskScore()
     */
    @Deprecated(since = "3.4.0", forRemoval = true)
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