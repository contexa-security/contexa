package io.contexa.contexacore.autonomous.tiered.util;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import lombok.extern.slf4j.Slf4j;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

@Slf4j
public class SecurityEventEnricher {

    private static final Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9+/=]{4,}$");
    
    private static final Pattern URL_ENCODED_PATTERN = Pattern.compile(".*%[0-9A-Fa-f]{2}.*");

    public static final String TARGET_RESOURCE = "targetResource";
    
    public static final String REQUEST_PAYLOAD = "requestPayload";
    public static final String USER_BEHAVIOR = "userBehavior";
    public static final String PATTERN_SCORE = "patternScore";
    public static final String RISK_INDICATORS = "riskIndicators";
    public static final String CONTEXT_EMBEDDINGS = "contextEmbeddings";
    public static final String LAYER_DECISIONS = "layerDecisions";
    public static final String PROCESSING_TIMESTAMP = "processingTimestamp";
    public static final String CORRELATION_ID = "correlationId";

    public void enrichEvent(SecurityEvent event, String key, Object value) {
        if (event == null) {
            return;
        }
        if (event.getMetadata() == null) {
            event.setMetadata(new HashMap<>());
        }
        event.getMetadata().put(key, value);
    }

    public void setTargetResource(SecurityEvent event, String targetResource) {
        enrichEvent(event, TARGET_RESOURCE, targetResource);
    }

    public Optional<String> getTargetResource(SecurityEvent event) {
        
        Optional<String> target = getMetadataValue(event, TARGET_RESOURCE, String.class);
        if (target.isPresent()) {
            return target;
        }

        Optional<String> requestUri = getMetadataValue(event, "requestUri", String.class);
        if (requestUri.isPresent()) {
            return requestUri;
        }

        return getMetadataValue(event, "fullPath", String.class);
    }

    public void setRequestPayload(SecurityEvent event, Object payload) {
        enrichEvent(event, REQUEST_PAYLOAD, payload);
    }

    public Optional<Object> getRequestPayload(SecurityEvent event) {
        return getMetadataValue(event, REQUEST_PAYLOAD, Object.class);
    }

    public Optional<String> getDecodedPayload(SecurityEvent event) {
        return getRequestPayload(event)
                .map(payload -> {
                    if (payload == null) {
                        return null;
                    }
                    String payloadStr = payload.toString();
                    return decodePayload(payloadStr);
                })
                .filter(Objects::nonNull);
    }

    private String decodePayload(String payload) {
        if (payload == null || payload.isEmpty()) {
            return payload;
        }

        String decoded = payload;

        if (URL_ENCODED_PATTERN.matcher(payload).matches()) {
            try {
                decoded = URLDecoder.decode(payload, StandardCharsets.UTF_8);
                            } catch (Exception e) {
                            }
        }

        if (isLikelyBase64(decoded)) {
            try {
                byte[] decodedBytes = Base64.getDecoder().decode(decoded);
                String base64Decoded = new String(decodedBytes, StandardCharsets.UTF_8);
                
                if (isPrintable(base64Decoded)) {
                                        decoded = base64Decoded;
                }
            } catch (Exception e) {
                            }
        }

        return decoded;
    }

    private boolean isLikelyBase64(String str) {
        if (str == null || str.length() < 8) {
            return false;
        }
        
        return str.length() % 4 == 0 && BASE64_PATTERN.matcher(str).matches();
    }

    private boolean isPrintable(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        
        long printableCount = str.chars()
                .filter(c -> c >= 32 && c < 127)
                .count();
        return (double) printableCount / str.length() >= 0.8;
    }

    private String truncateForLog(String str) {
        if (str == null) return "null";
        if (str.length() <= 50) return str;
        return str.substring(0, 47) + "...";
    }

    public void setUserBehavior(SecurityEvent event, Map<String, Object> behavior) {
        enrichEvent(event, USER_BEHAVIOR, behavior);
    }

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

    public void setPatternScore(SecurityEvent event, Double score) {
        enrichEvent(event, PATTERN_SCORE, score);
    }

    public Optional<Double> getPatternScore(SecurityEvent event) {
        return getMetadataValue(event, PATTERN_SCORE, Double.class);
    }

    public void setRiskIndicators(SecurityEvent event, Map<String, Object> indicators) {
        enrichEvent(event, RISK_INDICATORS, indicators);
    }

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

    public void setContextEmbeddings(SecurityEvent event, float[] embeddings) {
        enrichEvent(event, CONTEXT_EMBEDDINGS, embeddings);
    }

    public Optional<float[]> getContextEmbeddings(SecurityEvent event) {
        return getMetadataValue(event, CONTEXT_EMBEDDINGS, float[].class);
    }

    @SuppressWarnings("unchecked")
    public void addLayerDecision(SecurityEvent event, String layer, Map<String, Object> decision) {
        Map<String, Object> decisions = (Map<String, Object>) event.getMetadata()
            .computeIfAbsent(LAYER_DECISIONS, k -> new HashMap<String, Object>());
        decisions.put(layer, decision);
    }

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

    public void setCorrelationId(SecurityEvent event, String correlationId) {
        enrichEvent(event, CORRELATION_ID, correlationId);
    }

    public Optional<String> getCorrelationId(SecurityEvent event) {
        return getMetadataValue(event, CORRELATION_ID, String.class);
    }

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

        if (Number.class.isAssignableFrom(type) && value instanceof Number) {
            try {
                Number numValue = (Number) value;
                Object converted = convertNumber(numValue, type);
                if (converted != null) {
                    return Optional.of((T) converted);
                }
            } catch (Exception e) {
                            }
        }

        if (Number.class.isAssignableFrom(type) && value instanceof String) {
            try {
                Object converted = parseStringToNumber((String) value, type);
                if (converted != null) {
                    return Optional.of((T) converted);
                }
            } catch (Exception e) {
                            }
        }

        if (type == String.class) {
            return Optional.of((T) value.toString());
        }

        log.warn("[SecurityEventEnricher] Type mismatch for key '{}': expected {}, got {}",
                key, type.getSimpleName(), value.getClass().getSimpleName());
        return Optional.empty();
    }

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

    public boolean hasMetadata(SecurityEvent event, String key) {
        return event.getMetadata() != null && event.getMetadata().containsKey(key);
    }

    public Map<String, Object> createEventContext(SecurityEvent event) {
        Map<String, Object> context = new HashMap<>();

        context.put("eventId", event.getEventId());
        context.put("severity", event.getSeverity());
        context.put("timestamp", event.getTimestamp());

        if (event.getSourceIp() != null) {
            context.put("sourceIp", event.getSourceIp());
        }

        if (event.getUserId() != null) {
            context.put("userId", event.getUserId());
        }
        if (event.getSessionId() != null) {
            context.put("sessionId", event.getSessionId());
        }

        getTargetResource(event).ifPresent(resource -> context.put("targetResource", resource));
        getPatternScore(event).ifPresent(score -> context.put("patternScore", score));
        
        return context;
    }

    @Deprecated(since = "3.4.0", forRemoval = true)
    public double calculateRiskScore(SecurityEvent event) {
        double baseScore = 0.0;

        if (event.getSeverity() != null) {
            baseScore = event.getSeverity().getScore() / 10.0; 
        }

        getPatternScore(event).ifPresent(score -> {
            
        });

        getRiskIndicators(event).ifPresent(indicators -> {
            
        });
        
        return Math.min(1.0, Math.max(0.0, baseScore)); 
    }

    public String generateEventSummary(SecurityEvent event) {
        StringBuilder summary = new StringBuilder();
        
        summary.append("Event[").append(event.getEventId()).append("]: ");
        summary.append("Severity=").append(event.getSeverity()).append(" ");
        
        if (event.getUserId() != null) {
            summary.append("User:").append(event.getUserId()).append(" ");
        }
        
        if (event.getSourceIp() != null) {
            summary.append("From:").append(event.getSourceIp()).append(" ");
        }
        
        getTargetResource(event).ifPresent(resource ->
            summary.append("Target:").append(resource).append(" ")
        );

        return summary.toString().trim();
    }
}