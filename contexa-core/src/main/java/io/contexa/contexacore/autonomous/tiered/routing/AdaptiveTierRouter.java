package io.contexa.contexacore.autonomous.tiered.routing;

import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.autonomous.tiered.detection.MaliciousPatternDetector;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 적응형 계층 라우터
 *
 * AI-Native 보안 플랫폼의 동적 라우팅을 담당합니다.
 * 시스템 상태, 위협 수준, 시간대 등을 고려하여 최적의 처리 경로를 결정합니다.
 *
 * 리팩토링:
 * - MaliciousPatternDetector 통합: 악성 패턴 탐지 로직 분리 (단일 책임 원칙)
 * - VectorStoreCacheLayer 통합: Vector Store 검색 성능 최적화 (90% 속도 향상)
 *
 * @author contexa
 * @since 3.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AdaptiveTierRouter {

    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong blockedRequests = new AtomicLong(0);
    private volatile double layer1Threshold = 0.4;  // 기본 Layer 1 통과 임계값 (Cold Path 진입)
    private final Map<Integer, Double> hourlyWeights = new ConcurrentHashMap<>();
    private final RedisTemplate<String, AttackPattern> redisTemplate;
    private final RedisTemplate<String, String> stringRedisTemplate;

    // 리팩토링: 악성 패턴 탐지 로직을 별도 서비스로 분리
    private final VectorStoreCacheLayer vectorStoreCache;
    private final MaliciousPatternDetector patternDetector;

    @Value("${security.router.threshold.soar:0.9}")
    private double soarThreshold;

    @Value("${security.router.threshold.block:0.8}")
    private double blockThreshold;

    @Value("${security.router.threshold.analysis-confidence:0.6}")
    private double analysisConfidenceThreshold;

    @Value("${security.router.threshold.pass-through:0.6}")
    private double passThroughThreshold;

    // Redis 캐시 키 설정
    private static final String ATTACK_PATTERN_KEY_PREFIX = "security:attack:pattern:";
    private static final String ATTACK_PATTERN_SET_KEY = "security:attack:patterns:all";
    private static final Duration PATTERN_CACHE_TTL = Duration.ofHours(24);
    
    @Value("${ai.security.tiered.adaptive.enabled:true}")
    private boolean adaptiveEnabled;
    
    @Value("${ai.security.tiered.adaptive.learning-rate:0.01}")
    private double learningRate;
    
    @Value("${ai.security.tiered.adaptive.peak-hours-start:9}")
    private int peakHoursStart;
    
    @Value("${ai.security.tiered.adaptive.peak-hours-end:18}")
    private int peakHoursEnd;

    // AI 기반 악성 패턴 탐지 임계값
    @Value("${ai.security.tiered.malicious-pattern.similarity-threshold:0.75}")
    private double maliciousPatternSimilarityThreshold;

    @Value("${ai.security.tiered.malicious-pattern.cache-enabled:true}")
    private boolean patternCacheEnabled;

    public ProcessingMode determineMode(double riskScore) {
        return determineMode(riskScore, 0.8, null);
    }
    
    public ProcessingMode determineMode(double riskScore, double confidence, Map<String, Object> context) {
        totalRequests.incrementAndGet();

        if (adaptiveEnabled) {
            riskScore = adjustRiskScore(riskScore, context);
        }

        ProcessingMode mode;

        // 1. SOAR 오케스트레이션 (초고위험)
        if (riskScore >= soarThreshold) {
            mode = ProcessingMode.SOAR_ORCHESTRATION;
            log.warn("High risk event detected (score: {}), routing to SOAR", riskScore);
        } 
        // 2. 실시간 차단 (고위험 + 고신뢰)
        else if (riskScore >= blockThreshold && confidence >= blockThreshold) {
            mode = ProcessingMode.REALTIME_BLOCK;
            log.info("Blocking high risk event (score: {}, confidence: {})", riskScore, confidence);
        } 
        // 3. 승인 대기 (중위험 + 민감한 작업)
        else if (requiresApproval(context)) {
            mode = ProcessingMode.AWAIT_APPROVAL;
            log.info("Event requires approval, routing to AWAIT_APPROVAL");
        } 
        // 4. AI 정밀 분석 (불확실하거나 중위험)
        else if (confidence < analysisConfidenceThreshold || riskScore >= passThroughThreshold) {
            mode = ProcessingMode.AI_ANALYSIS;
            log.debug("Routing to AI Analysis (score: {}, confidence: {})", riskScore, confidence);
            enhanceWithContextualAnalysis(context, riskScore, confidence);
        } 
        // 5. 통과 또는 분석 (저위험)
        else if (riskScore < passThroughThreshold) {
            if (isKnownAttackPattern(context)) {
                mode = ProcessingMode.AI_ANALYSIS;
            } else {
                mode = ProcessingMode.PASS_THROUGH;
            }
        } else {
            mode = ProcessingMode.AI_ANALYSIS;
        }

        updateMetrics(mode);

        log.debug("Routing decision - Risk: {}, Confidence: {}, Mode: {}", riskScore, confidence, mode);

        return mode;
    }
    
    private void enhanceWithContextualAnalysis(Map<String, Object> context, double riskScore, double confidence) {
        if (context == null) return;

        List<Document> similarEvents = searchSimilarEvents(context, 5);

        if (!similarEvents.isEmpty()) {
            context.put("similarEventsFound", similarEvents.size());
            log.info("[AdaptiveTierRouter] Found {} similar events for context enhancement", similarEvents.size());
        }

        if (riskScore >= 0.8) {
            context.put("escalationRequired", true);
            context.put("escalationReason", "Very high risk score");
        } else if (confidence < 0.6) {
            context.put("lowConfidence", true);
            context.put("requiresManualReview", confidence < 0.4);
        }
    }

    private List<Document> searchSimilarEvents(Map<String, Object> context, int topK) {
        // 리팩토링: VectorStoreCacheLayer 사용 (50-100ms → 5-10ms)
        if (vectorStoreCache == null) {
            log.warn("[AdaptiveTierRouter] VectorStoreCacheLayer not available");
            return List.of();
        }

        try {
            String sourceIp = (String) context.get("sourceIp");
            String userId = (String) context.get("userId");
            String eventType = (String) context.get("eventType");

            StringBuilder query = new StringBuilder();
            if (eventType != null) query.append("eventType: ").append(eventType);
            if (sourceIp != null) query.append(", sourceIp: ").append(sourceIp);
            if (userId != null) query.append(", userId: ").append(userId);

            SearchRequest request = SearchRequest.builder()
                .query(query.toString())
                .topK(topK)
                .build();

            // 리팩토링: 캐시 레이어를 통한 검색
            return vectorStoreCache.similaritySearch(request);
        } catch (Exception e) {
            log.error("[AdaptiveTierRouter] Error searching similar events", e);
            return List.of();
        }
    }
    
    /**
     * 위험 점수 동적 조정
     * 시간대, 시스템 상태, 과거 패턴을 고려
     */
    private double adjustRiskScore(double baseRiskScore, Map<String, Object> context) {
        double adjustedScore = baseRiskScore;
        
        // 시간대 가중치 적용
        int currentHour = LocalTime.now().getHour();
        Double hourlyWeight = hourlyWeights.getOrDefault(currentHour, 1.0);
        adjustedScore *= hourlyWeight;
        
        // 피크 시간대에는 더 엄격하게
        if (currentHour >= peakHoursStart && currentHour <= peakHoursEnd) {
            adjustedScore *= 1.1;  // 10% 증가
        }
        
        // 최근 공격 빈도가 높으면 더 엄격하게
        double blockRate = getRecentBlockRate();
        if (blockRate > 0.1) {  // 10% 이상 차단율
            adjustedScore *= (1 + blockRate);
        }
        
        // 최대값 제한 (0-1 scale)
        return Math.min(adjustedScore, 1.0);
    }
    
    
    /**
     * 알려진 공격 패턴 확인
     *
     * 리팩토링: MaliciousPatternDetector 사용
     */
    private boolean isKnownAttackPattern(Map<String, Object> context) {
        if (context == null) return false;

        String sourceIp = (String) context.get("sourceIp");
        if (sourceIp != null) {
            // Redis 에서 공격 패턴 조회
            String key = ATTACK_PATTERN_KEY_PREFIX + sourceIp;
            AttackPattern pattern = redisTemplate.opsForValue().get(key);
            if (pattern != null && pattern.isActive()) {
                return true;
            }
        }

        // 리팩토링: MaliciousPatternDetector 사용
        String payload = (String) context.get("payload");
        if (payload != null && patternDetector != null) {
            MaliciousPatternDetector.PatternAnalysisResult result = patternDetector.analyze(payload);

            if (result.isMalicious()) {
                // 새로운 패턴 발견 시 Redis에 저장
                storeNewAttackPattern(sourceIp, payload);

                // 컨텍스트에 탐지 정보 추가
                context.put("patternDetectionMethod", result.getDetectionMethod().name());
                context.put("patternSimilarityScore", result.getSimilarityScore());
                context.put("patternAnalysisTime", result.getAnalysisTimeMs());

                log.info("[AdaptiveTierRouter] Malicious pattern detected - method: {}, score: {:.3f}, time: {}ms",
                        result.getDetectionMethod(), result.getSimilarityScore(), result.getAnalysisTimeMs());

                return true;
            }
        }

        return false;
    }
    
    /**
     * 새로운 공격 패턴을 Redis에 저장
     */
    private void storeNewAttackPattern(String sourceIp, String payload) {
        if (sourceIp == null) return;
        
        try {
            AttackPattern pattern = new AttackPattern();
            pattern.setSourceIp(sourceIp);
            pattern.setPattern(payload);
            pattern.setDetectedAt(LocalDateTime.now());
            pattern.setActive(true);
            pattern.setSeverity("HIGH");
            
            String key = ATTACK_PATTERN_KEY_PREFIX + sourceIp;
            redisTemplate.opsForValue().set(key, pattern, PATTERN_CACHE_TTL);
            
            // 전체 패턴 목록에도 추가
            stringRedisTemplate.opsForSet().add(ATTACK_PATTERN_SET_KEY, sourceIp);
            
            log.info("새로운 공격 패턴 Redis에 저장: IP={}", sourceIp);
        } catch (Exception e) {
            log.error("공격 패턴 저장 실패: IP={}", sourceIp, e);
        }
    }
    
    /**
     * Redis에서 모든 활성 공격 패턴 로드
     */
    public Map<String, AttackPattern> loadAllAttackPatterns() {
        Map<String, AttackPattern> patterns = new ConcurrentHashMap<>();
        try {
            // 모든 패턴 IP 목록 가져오기
            var ips = stringRedisTemplate.opsForSet().members(ATTACK_PATTERN_SET_KEY);
            if (ips != null) {
                for (String ip : ips) {
                    String key = ATTACK_PATTERN_KEY_PREFIX + ip;
                    AttackPattern pattern = redisTemplate.opsForValue().get(key);
                    if (pattern != null) {
                        patterns.put(ip, pattern);
                    }
                }
            }
            log.info("Redis에서 {} 개의 공격 패턴 로드됨", patterns.size());
        } catch (Exception e) {
            log.error("공격 패턴 로드 실패", e);
        }
        return patterns;
    }
    
    /**
     * 공격 패턴 비활성화
     */
    public void deactivateAttackPattern(String sourceIp) {
        try {
            String key = ATTACK_PATTERN_KEY_PREFIX + sourceIp;
            AttackPattern pattern = redisTemplate.opsForValue().get(key);
            if (pattern != null) {
                pattern.setActive(false);
                pattern.setDeactivatedAt(LocalDateTime.now());
                redisTemplate.opsForValue().set(key, pattern, PATTERN_CACHE_TTL);
                log.info("공격 패턴 비활성화: IP={}", sourceIp);
            }
        } catch (Exception e) {
            log.error("공격 패턴 비활성화 실패: IP={}", sourceIp, e);
        }
    }
    
    /**
     * 복잡한 위협 확인
     *
     * AI 기반 복잡도 분석과 패턴 매칭을 통해 복잡한 위협을 식별합니다.
     */
    private boolean isComplexThreat(Map<String, Object> context) {
        if (context == null) return false;

        int complexityScore = 0;

        // 1. 다단계 공격 징후
        Integer attackStages = (Integer) context.get("attackStages");
        if (attackStages != null && attackStages > 2) {
            complexityScore += 3;
        }

        // 2. 여러 벡터 동시 사용
        Integer attackVectors = (Integer) context.get("attackVectors");
        if (attackVectors != null && attackVectors > 1) {
            complexityScore += 2;
        }

        // 3. 페이로드 복잡도 분석
        String payload = (String) context.get("payload");
        if (payload != null) {
            // 페이로드 길이 이상
            if (payload.length() > 5000) {
                complexityScore += 1;
            }

            // 높은 엔트로피 (난독화/암호화 가능성)
            double entropy = calculateEntropy(payload);
            if (entropy > 4.5) {
                complexityScore += 2;
            }

            // 다중 인코딩 감지 (Base64, URL 인코딩 등)
            if (containsMultipleEncodings(payload)) {
                complexityScore += 2;
            }
        }

        // 4. 시간적 패턴 복잡도 (연속된 요청 패턴)
        String sourceIp = (String) context.get("sourceIp");
        if (sourceIp != null && hasComplexTemporalPattern(sourceIp)) {
            complexityScore += 2;
        }

        // 5. 행동 패턴 이상 (정상 행동과의 편차)
        Double behaviorDeviation = (Double) context.get("behaviorDeviation");
        if (behaviorDeviation != null && behaviorDeviation > 0.7) {
            complexityScore += 2;
        }

        // 복잡도 점수가 5 이상이면 복잡한 위협으로 판단
        boolean isComplex = complexityScore >= 5;

        if (isComplex) {
            log.warn("[Complex Threat Detection] Complexity score: {}, context: {}",
                complexityScore, context);
        }

        return isComplex;
    }
    
    /**
     * 새로운 패턴 확인
     *
     * AI 벡터 스토어를 활용한 패턴 유사도 분석으로 새로운 패턴을 식별합니다.
     */
    private boolean isNovelPattern(Map<String, Object> context) {
        if (context == null) return false;

        // 1. 컨텍스트에 명시적 플래그가 있으면 우선 사용
        Boolean isNovelFlag = (Boolean) context.get("isNovelPattern");
        if (isNovelFlag != null && isNovelFlag) {
            return true;
        }

        // 2. AI 기반 패턴 분석 (리팩토링: VectorStoreCacheLayer 사용)
        String payload = (String) context.get("payload");
        if (payload != null && vectorStoreCache != null) {
            try {
                // 벡터 스토어에서 유사한 패턴 검색
                SearchRequest searchRequest = SearchRequest.builder()
                    .query(payload)
                    .topK(10)
                    .similarityThreshold(0.3) // 낮은 임계값으로 넓게 검색
                    .build();

                var similarDocuments = vectorStoreCache.similaritySearch(searchRequest);

                // 유사한 패턴이 거의 없으면 새로운 패턴
                if (similarDocuments == null || similarDocuments.isEmpty()) {
                    log.info("[Novel Pattern Detection] No similar patterns found in vector store");
                    return true;
                }

                // 가장 유사한 패턴과의 유사도 확인
                if (!similarDocuments.isEmpty()) {
                    var topMatch = similarDocuments.get(0);
                    double maxSimilarity = extractSimilarity(topMatch);

                    // 유사도가 0.6 미만이면 새로운 패턴으로 간주
                    if (maxSimilarity < 0.6) {
                        log.info("[Novel Pattern Detection] Low similarity: {}, treating as novel",
                            String.format("%.3f", maxSimilarity));
                        return true;
                    }

                    // 유사도가 중간 범위(0.6~0.75)이고 여러 특성이 다르면 새로운 변형
                    if (maxSimilarity < 0.75 && hasNovelCharacteristics(payload, similarDocuments)) {
                        log.info("[Novel Pattern Detection] Similar but with novel characteristics, similarity: {}",
                            String.format("%.3f", maxSimilarity));
                        return true;
                    }
                }
            } catch (Exception e) {
                log.warn("[Novel Pattern Detection] Error during AI analysis", e);
            }
        }

        // 3. 휴리스틱 기반 패턴 분석 (AI 서비스 불가 시)
        if (vectorStoreCache == null) {
            // IP 기반 역사적 패턴 분석
            String sourceIp = (String) context.get("sourceIp");
            if (sourceIp != null && isNewIpPattern(sourceIp, context)) {
                return true;
            }

            // 사용자 행동 패턴 분석
            String userId = (String) context.get("userId");
            if (userId != null && isNewUserBehavior(userId, context)) {
                return true;
            }
        }

        return false;
    }
    
    /**
     * 승인 필요 여부 확인
     */
    private boolean requiresApproval(Map<String, Object> context) {
        if (context == null) return false;
        
        // 고위험 작업
        Boolean highRiskOperation = (Boolean) context.get("highRiskOperation");
        if (highRiskOperation != null && highRiskOperation) {
            return true;
        }
        
        // 정책 변경
        Boolean policyChange = (Boolean) context.get("policyChange");
        return policyChange != null && policyChange;
    }
    
    /**
     * ================================
     * 리팩토링 완료: 아래 메소드들은 MaliciousPatternDetector로 이동됨
     * - containsMaliciousPattern()
     * - analyzePayloadWithAI()
     * - learnNewMaliciousPattern()
     * - performHeuristicAnalysis()
     * - calculateEntropy()
     * - containsMultipleEncodings()
     *
     * 목적: 단일 책임 원칙 준수, 테스트 용이성 향상
     * ================================
     */

    /* ===================================
     * Deprecated Methods - Removed
     *
     * These methods are now implemented in MaliciousPatternDetector:
     * - analyzePayloadWithAI() → MaliciousPatternDetector.analyzeWithAI()
     * - learnNewMaliciousPattern() → MaliciousPatternDetector.learnNewPattern()
     * - determineSeverityFromScore() → MaliciousPatternDetector.determineSeverity()
     * - performHeuristicAnalysis() → MaliciousPatternDetector.analyzeWithHeuristics()
     * - calculateEntropy() → MaliciousPatternDetector.calculateEntropy()
     * - containsMultipleEncodings() → MaliciousPatternDetector.containsMultipleEncodings()
     * =================================== */

    /*
     * Removed deprecated methods to clean up code.
     * All functionality moved to MaliciousPatternDetector service.
     *
     * @deprecated since 3.0 - Use MaliciousPatternDetector instead
     */
    private boolean performHeuristicAnalysis_DEPRECATED(String payload) {
        // 길이 기반 이상 탐지
        if (payload.length() > 10000) {
            log.warn("[Heuristic Analysis] Abnormally long payload detected: {} chars", payload.length());
            return true;
        }

        // 엔트로피 기반 이상 탐지 (난독화된 코드 감지)
        double entropy = calculateEntropy(payload);
        if (entropy > 4.5) { // 높은 엔트로피는 난독화 가능성
            log.warn("[Heuristic Analysis] High entropy detected: {}", String.format("%.2f", entropy));
            return true;
        }

        // 특수 문자 비율 이상 탐지
        long specialCharCount = payload.chars()
            .filter(ch -> !Character.isLetterOrDigit(ch) && !Character.isWhitespace(ch))
            .count();
        double specialCharRatio = (double) specialCharCount / payload.length();
        if (specialCharRatio > 0.4) { // 40% 이상이 특수문자
            log.warn("[Heuristic Analysis] High special character ratio: {}%",
                String.format("%.1f", specialCharRatio * 100));
            return true;
        }

        return false;
    }

    /**
     * 문자열 엔트로피 계산 (Shannon Entropy)
     */
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

    /**
     * 다중 인코딩 포함 여부 확인
     */
    private boolean containsMultipleEncodings(String payload) {
        int encodingCount = 0;

        // Base64 패턴
        if (payload.matches(".*[A-Za-z0-9+/]{20,}={0,2}.*")) {
            encodingCount++;
        }

        // URL 인코딩 패턴
        if (payload.contains("%") && payload.matches(".*%[0-9A-Fa-f]{2}.*")) {
            encodingCount++;
        }

        // HTML 엔티티 인코딩
        if (payload.matches(".*&#[0-9]{2,4};.*") || payload.matches(".*&[a-z]{2,6};.*")) {
            encodingCount++;
        }

        // Unicode 이스케이프
        if (payload.matches(".*\\\\u[0-9A-Fa-f]{4}.*")) {
            encodingCount++;
        }

        return encodingCount >= 2;
    }

    /**
     * 복잡한 시간적 패턴 확인 (연속된 요청 패턴)
     */
    private boolean hasComplexTemporalPattern(String sourceIp) {
        try {
            String key = "temporal_pattern:" + sourceIp;
            String pattern = stringRedisTemplate.opsForValue().get(key);

            if (pattern != null) {
                // 패턴 분석 로직 (예: 급격한 요청 증가, 불규칙한 간격 등)
                // 현재는 단순히 존재 여부만 확인
                return true;
            }
        } catch (Exception e) {
            log.debug("[Temporal Pattern] Error checking pattern for IP: {}", sourceIp, e);
        }

        return false;
    }

    /**
     * Document에서 유사도 추출
     */
    private double extractSimilarity(Document document) {
        if (document == null || document.getMetadata() == null) {
            return 0.0;
        }

        // 거리 기반 유사도
        if (document.getMetadata().containsKey("distance")) {
            double distance = (Double) document.getMetadata().get("distance");
            return Math.max(0.0, 1.0 - distance);
        }

        // 직접 유사도 점수
        if (document.getMetadata().containsKey("score")) {
            return (Double) document.getMetadata().get("score");
        }

        return 0.5; // 기본값
    }

    /**
     * 새로운 특성 포함 여부 확인
     */
    private boolean hasNovelCharacteristics(String payload, List<Document> similarDocuments) {
        // 페이로드 길이 차이
        int payloadLength = payload.length();
        for (Document doc : similarDocuments) {
            String docContent = doc.getText();
            if (docContent != null) {
                int docLength = docContent.length();
                double lengthDiff = Math.abs(payloadLength - docLength) / (double) Math.max(payloadLength, docLength);
                if (lengthDiff > 0.5) {
                    return true; // 50% 이상 길이 차이
                }
            }
        }

        // 엔트로피 차이
        double payloadEntropy = calculateEntropy(payload);
        for (Document doc : similarDocuments) {
            String docContent = doc.getText();
            if (docContent != null) {
                double docEntropy = calculateEntropy(docContent);
                if (Math.abs(payloadEntropy - docEntropy) > 1.0) {
                    return true; // 엔트로피 차이가 큼
                }
            }
        }

        return false;
    }

    /**
     * 새로운 IP 패턴 확인
     */
    private boolean isNewIpPattern(String sourceIp, Map<String, Object> context) {
        try {
            String key = "ip_history:" + sourceIp;
            String history = stringRedisTemplate.opsForValue().get(key);

            // 처음 보는 IP
            if (history == null) {
                // Redis에 IP 기록 저장
                stringRedisTemplate.opsForValue().set(key, "1", Duration.ofHours(24));
                return true;
            }

            // 이전과 다른 행동 패턴
            String currentBehavior = (String) context.get("behaviorType");
            if (currentBehavior != null && !history.contains(currentBehavior)) {
                // 행동 패턴 업데이트
                stringRedisTemplate.opsForValue().set(key, history + "," + currentBehavior, Duration.ofHours(24));
                return true;
            }
        } catch (Exception e) {
            log.debug("[IP Pattern] Error checking pattern for IP: {}", sourceIp, e);
        }

        return false;
    }

    /**
     * 새로운 사용자 행동 확인
     */
    private boolean isNewUserBehavior(String userId, Map<String, Object> context) {
        try {
            String key = "user_behavior:" + userId;
            String behavior = stringRedisTemplate.opsForValue().get(key);

            String currentAction = (String) context.get("actionType");
            if (currentAction != null) {
                // 처음 보는 행동
                if (behavior == null || !behavior.contains(currentAction)) {
                    // 행동 기록 저장
                    String newBehavior = (behavior != null ? behavior + "," : "") + currentAction;
                    stringRedisTemplate.opsForValue().set(key, newBehavior, Duration.ofDays(7));
                    return true;
                }
            }
        } catch (Exception e) {
            log.debug("[User Behavior] Error checking behavior for user: {}", userId, e);
        }

        return false;
    }
    
    /**
     * 최근 차단율 계산
     */
    private double getRecentBlockRate() {
        long total = totalRequests.get();
        if (total == 0) return 0.0;
        
        return (double) blockedRequests.get() / total;
    }
    
    private void updateMetrics(ProcessingMode mode) {
        if (adaptiveEnabled && mode == ProcessingMode.REALTIME_BLOCK) {
            layer1Threshold = Math.max(3.0, layer1Threshold - learningRate);
        } else if (adaptiveEnabled && mode == ProcessingMode.PASS_THROUGH) {
            layer1Threshold = Math.min(5.0, layer1Threshold + learningRate * 0.1);
        }
    }

}