package io.contexa.contexacore.autonomous.tiered.detection;

import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

@Slf4j
@RequiredArgsConstructor
public class MaliciousPatternDetector {

    @Autowired(required = false)
    private VectorStoreCacheLayer vectorStoreCacheLayer;

    private final RedisTemplate<String, String> stringRedisTemplate;

    @Value("${spring.ai.security.pattern-detection.min-similarity-filter:0.5}")
    private double minSimilarityFilter;

    @Value("${spring.ai.security.pattern-detection.cache-enabled:true}")
    private boolean cacheEnabled;

    @Value("${spring.ai.security.pattern-detection.auto-learn:true}")
    private boolean autoLearn;

    @Value("${spring.ai.security.pattern-detection.heuristic-enabled:true}")
    private boolean heuristicEnabled;

    public PatternAnalysisResult analyze(String payload) {
        if (payload == null || payload.isEmpty()) {
            return PatternAnalysisResult.safe("Empty payload");
        }

        try {
            long startTime = System.currentTimeMillis();

            PatternAnalysisResult cachedResult = checkCache(payload);
            if (cachedResult != null) {
                long elapsedTime = System.currentTimeMillis() - startTime;
                cachedResult.setAnalysisTimeMs(elapsedTime);
                                return cachedResult;
            }

            PatternAnalysisResult aiResult = analyzeWithAI(payload);
            if (aiResult != null) {
                long elapsedTime = System.currentTimeMillis() - startTime;
                aiResult.setAnalysisTimeMs(elapsedTime);

                cacheResult(payload, aiResult);

                if (autoLearn && aiResult.isMalicious() && aiResult.getSimilarityScore() < 0.95) {
                    learnNewPattern(payload, aiResult);
                }

                                return aiResult;
            }

            PatternAnalysisResult heuristicResult = analyzeWithHeuristics(payload);
            long elapsedTime = System.currentTimeMillis() - startTime;
            heuristicResult.setAnalysisTimeMs(elapsedTime);

                        return heuristicResult;

        } catch (Exception e) {
            log.error("[PatternDetector] Error analyzing payload", e);
            return PatternAnalysisResult.error("Analysis failed: " + e.getMessage());
        }
    }

    private PatternAnalysisResult checkCache(String payload) {
        if (!cacheEnabled) {
            return null;
        }

        try {
            String cacheKey = "malicious_pattern_check:" + payload.hashCode();
            String cachedValue = stringRedisTemplate.opsForValue().get(cacheKey);

            if (cachedValue != null) {
                boolean isMalicious = Boolean.parseBoolean(cachedValue);
                return PatternAnalysisResult.builder()
                        .malicious(isMalicious)
                        .detectionMethod(DetectionMethod.CACHE)
                        .reason("Cached result")
                        .build();
            }
        } catch (Exception e) {
            log.warn("[PatternDetector] Cache check failed", e);
        }

        return null;
    }

    private PatternAnalysisResult analyzeWithAI(String payload) {
        if (vectorStoreCacheLayer == null) {
            return null;
        }

        try {
            
            SearchRequest searchRequest = SearchRequest.builder()
                    .query(payload)
                    .topK(5)
                    .similarityThreshold(0.5)  
                    .build();

            List<Document> similarDocuments = vectorStoreCacheLayer.similaritySearch(searchRequest);

            if (similarDocuments == null || similarDocuments.isEmpty()) {
                return PatternAnalysisResult.builder()
                        .malicious(false)
                        .similarityScore(0.0)
                        .detectionMethod(DetectionMethod.AI_VECTOR)
                        .reason("No similar malicious patterns found")
                        .build();
            }

            Document topMatch = similarDocuments.get(0);
            double maxSimilarity = extractSimilarity(topMatch);

            boolean hasHighSimilarity = maxSimilarity >= 0.7; 

            return PatternAnalysisResult.builder()
                    .malicious(hasHighSimilarity) 
                    .similarityScore(maxSimilarity)
                    .matchedPatternCount(similarDocuments.size())
                    .detectionMethod(DetectionMethod.AI_VECTOR)
                    .reason(String.format("Similarity to known patterns: %.2f%% (LLM will determine final action)", maxSimilarity * 100))
                    .matchedDocument(topMatch)
                    .build();

        } catch (Exception e) {
            log.warn("[PatternDetector] AI analysis failed", e);
            return null;
        }
    }

    private PatternAnalysisResult analyzeWithHeuristics(String payload) {
        if (!heuristicEnabled) {
            return PatternAnalysisResult.safe("Heuristic analysis disabled");
        }

        int suspicionScore = 0;
        StringBuilder reasons = new StringBuilder();

        if (payload.length() > 10000) {
            suspicionScore += 3;
            reasons.append("Abnormally long payload (").append(payload.length()).append(" chars); ");
        }

        double entropy = calculateEntropy(payload);
        if (entropy > 4.5) {
            suspicionScore += 3;
            reasons.append(String.format("High entropy (%.2f, possible obfuscation); ", entropy));
        }

        long specialCharCount = payload.chars()
                .filter(ch -> !Character.isLetterOrDigit(ch) && !Character.isWhitespace(ch))
                .count();
        double specialCharRatio = (double) specialCharCount / payload.length();
        if (specialCharRatio > 0.4) {
            suspicionScore += 2;
            reasons.append(String.format("High special char ratio (%.1f%%); ", specialCharRatio * 100));
        }

        if (containsMultipleEncodings(payload)) {
            suspicionScore += 2;
            reasons.append("Multiple encoding layers detected; ");
        }

        boolean isMalicious = suspicionScore >= 5;

        return PatternAnalysisResult.builder()
                .malicious(isMalicious)
                .suspicionScore(suspicionScore)
                .detectionMethod(DetectionMethod.HEURISTIC)
                .reason(isMalicious ? reasons.toString() : "No suspicious patterns detected")
                .entropy(entropy)
                .specialCharRatio(specialCharRatio)
                .build();
    }

    private void learnNewPattern(String payload, PatternAnalysisResult result) {
        CompletableFuture.runAsync(() -> {
            try {
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("detectedAt", LocalDateTime.now().toString());
                metadata.put("similarityScore", result.getSimilarityScore());
                metadata.put("source", "MaliciousPatternDetector");
                metadata.put("type", "malicious_pattern");
                metadata.put("severity", determineSeverity(result.getSimilarityScore()));

                Document document = new Document(
                        "malicious_pattern_" + System.currentTimeMillis(),
                        payload,
                        metadata
                );

            } catch (Exception e) {
                log.error("[PatternDetector] Failed to learn new pattern", e);
            }
        });
    }

    private void cacheResult(String payload, PatternAnalysisResult result) {
        if (!cacheEnabled) {
            return;
        }

        try {
            String cacheKey = "malicious_pattern_check:" + payload.hashCode();
            stringRedisTemplate.opsForValue().set(
                    cacheKey,
                    String.valueOf(result.isMalicious()),
                    Duration.ofHours(1)
            );
        } catch (Exception e) {
            log.warn("[PatternDetector] Failed to cache result", e);
        }
    }

    private double extractSimilarity(Document document) {
        if (document == null || document.getMetadata() == null) {
            return 0.0;
        }

        if (document.getMetadata().containsKey("distance")) {
            double distance = (Double) document.getMetadata().get("distance");
            return Math.max(0.0, 1.0 - distance);
        }

        if (document.getMetadata().containsKey("score")) {
            return (Double) document.getMetadata().get("score");
        }

        return 0.5;  
    }

    private double calculateEntropy(String text) {
        if (text == null || text.isEmpty()) {
            return 0;
        }

        Map<Character, Integer> freq = new HashMap<>();
        for (char c : text.toCharArray()) {
            freq.put(c, freq.getOrDefault(c, 0) + 1);
        }

        double entropy = 0;
        for (int count : freq.values()) {
            double probability = (double) count / text.length();
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }

        return entropy;
    }

    private boolean containsMultipleEncodings(String payload) {
        int encodingCount = 0;

        if (payload.matches(".*[A-Za-z0-9+/]{20,}={0,2}.*")) {
            encodingCount++;
        }

        if (payload.contains("%") && payload.matches(".*%[0-9A-Fa-f]{2}.*")) {
            encodingCount++;
        }

        if (payload.matches(".*&#[0-9]{2,4};.*") || payload.matches(".*&[a-z]{2,6};.*")) {
            encodingCount++;
        }

        if (payload.matches(".*\\\\u[0-9A-Fa-f]{4}.*")) {
            encodingCount++;
        }

        return encodingCount >= 2;
    }

    private String determineSeverity(double similarityScore) {

        if (similarityScore >= 0.9) {
            return "CRITICAL";
        } else if (similarityScore >= 0.8) {
            return "HIGH";
        } else if (similarityScore >= 0.7) {
            return "MEDIUM";
        } else {
            return "LOW";
        }
    }

    @Data
    @Builder
    public static class PatternAnalysisResult {
        private boolean malicious;
        private double similarityScore;
        private int suspicionScore;
        private int matchedPatternCount;
        private DetectionMethod detectionMethod;
        private String reason;
        private long analysisTimeMs;

        private Double entropy;
        private Double specialCharRatio;
        private Document matchedDocument;

        public static PatternAnalysisResult safe(String reason) {
            return PatternAnalysisResult.builder()
                    .malicious(false)
                    .reason(reason)
                    .detectionMethod(DetectionMethod.NONE)
                    .build();
        }

        public static PatternAnalysisResult error(String reason) {
            return PatternAnalysisResult.builder()
                    .malicious(false)
                    .reason(reason)
                    .detectionMethod(DetectionMethod.ERROR)
                    .build();
        }
    }

    public enum DetectionMethod {
        CACHE,          
        AI_VECTOR,      
        HEURISTIC,      
        NONE,           
        ERROR           
    }
}
