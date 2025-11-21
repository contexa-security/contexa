package io.contexa.contexacoreenterprise.autonomous.intelligence;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatIndicators;
import io.contexa.contexacore.std.rag.service.StandardVectorStoreService;
import org.springframework.ai.document.Document;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * AITuningService - AI 자율 튜닝 서비스
 * 
 * 보안 시스템의 AI 모델을 자동으로 튜닝하고 최적화하는 서비스입니다.
 * 오탐(False Positive) 학습, 파라미터 조정, 성능 최적화를 수행합니다.
 * 
 * @author contexa
 * @since 1.0
 */
@Slf4j
@RequiredArgsConstructor
public class AITuningService {
    
    // 기존 컴포넌트 재사용
    private final StandardVectorStoreService vectorStore;
    private final RedisTemplate<String, Object> redisTemplate;
    
    // 설정값
    @Value("${ai.tuning.enabled:true}")
    private boolean tuningEnabled;
    
    @Value("${ai.tuning.learning.rate:0.01}")
    private double learningRate;
    
    @Value("${ai.tuning.batch.size:100}")
    private int batchSize;
    
    @Value("${ai.tuning.evaluation.interval-hours:6}")
    private int evaluationIntervalHours;
    
    @Value("${ai.tuning.min.samples:50}")
    private int minSamplesForTuning;
    
    @Value("${ai.tuning.confidence.threshold:0.8}")
    private double confidenceThreshold;
    
    @Value("${ai.tuning.false.positive.penalty:0.3}")
    private double falsePositivePenalty;
    
    @Value("${ai.tuning.false.negative.penalty:0.7}")
    private double falseNegativePenalty;
    
    // 학습 데이터 저장소
    private final Map<String, LearningData> learningDataStore = new ConcurrentHashMap<>();
    
    // 모델 파라미터
    private final Map<String, ModelParameters> modelParameters = new ConcurrentHashMap<>();
    
    // 성능 메트릭
    private final Map<String, PerformanceMetrics> performanceMetrics = new ConcurrentHashMap<>();
    
    // 튜닝 히스토리
    private final List<TuningHistory> tuningHistory = Collections.synchronizedList(new ArrayList<>());
    
    // 통계
    private final AtomicLong totalTuningCycles = new AtomicLong(0);
    private final AtomicLong successfulTunings = new AtomicLong(0);
    private final AtomicLong falsePositivesLearned = new AtomicLong(0);
    private final AtomicLong falseNegativesLearned = new AtomicLong(0);
    
    @PostConstruct
    public void initialize() {
        if (!tuningEnabled) {
            log.info("AI 자율 튜닝 비활성화됨");
            return;
        }
        
        log.info("AI 자율 튜닝 서비스 초기화 시작");
        
        // 기본 모델 파라미터 초기화
        initializeModelParameters();
        
        // 기존 학습 데이터 로드
        loadExistingLearningData();
        
        // 성능 기준선 설정
        establishPerformanceBaseline();
        
        log.info("AI 자율 튜닝 서비스 초기화 완료");
    }
    
    /**
     * 오탐(False Positive) 학습
     * 
     * @param event 오탐으로 판정된 이벤트
     * @param feedback 사용자 피드백
     * @return 학습 결과
     */
    public Mono<LearningResult> learnFalsePositive(SecurityEvent event, UserFeedback feedback) {
        if (!tuningEnabled) {
            return Mono.just(LearningResult.disabled());
        }
        
        return Mono.defer(() -> {
            String modelId = determineModelId(event);
            
            // 학습 데이터 수집
            LearningData data = learningDataStore.computeIfAbsent(modelId, k -> new LearningData());
            data.addFalsePositive(event, feedback);
            falsePositivesLearned.incrementAndGet();
            
            // 벡터 스토어에 패턴 저장
            saveFalsePositivePattern(event, feedback);
            
            // 즉시 튜닝이 필요한지 확인
            if (shouldTuneImmediately(data)) {
                return performTuning(modelId, data);
            }
            
            return Mono.just(LearningResult.queued(modelId));
        })
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    /**
     * 미탐(False Negative) 학습
     */
    public Mono<LearningResult> learnFalseNegative(SecurityEvent missedEvent, ThreatIndicators indicators) {
        if (!tuningEnabled) {
            return Mono.just(LearningResult.disabled());
        }
        
        return Mono.defer(() -> {
            String modelId = determineModelId(missedEvent);
            
            // 학습 데이터 수집
            LearningData data = learningDataStore.computeIfAbsent(modelId, k -> new LearningData());
            data.addFalseNegative(missedEvent, indicators);
            falseNegativesLearned.incrementAndGet();
            
            // 벡터 스토어에 패툄 저장
            saveFalseNegativePattern(missedEvent, indicators);
            
            // 즉시 튜닝이 필요한지 확인
            if (shouldTuneImmediately(data)) {
                return performTuning(modelId, data);
            }
            
            return Mono.just(LearningResult.queued(modelId));
        })
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    /**
     * 파라미터 최적화 제안
     * 
     * @param modelId 모델 ID
     * @return 최적화 제안
     */
    public Mono<TuningRecommendation> recommendTuning(String modelId) {
        return Mono.fromCallable(() -> {
            ModelParameters current = modelParameters.get(modelId);
            if (current == null) {
                return TuningRecommendation.noRecommendation();
            }
            
            PerformanceMetrics metrics = performanceMetrics.get(modelId);
            if (metrics == null) {
                return TuningRecommendation.noRecommendation();
            }
            
            // 성능 분석
            double falsePositiveRate = metrics.getFalsePositiveRate();
            double falseNegativeRate = metrics.getFalseNegativeRate();
            double precision = metrics.getPrecision();
            double recall = metrics.getRecall();
            double f1Score = metrics.getF1Score();
            
            Map<String, Double> adjustments = new HashMap<>();
            String rationale = "";
            
            // 오탐율이 높은 경우
            if (falsePositiveRate > 0.1) {
                adjustments.put("threshold", current.getThreshold() * 1.1);
                adjustments.put("sensitivity", current.getSensitivity() * 0.9);
                rationale += "오탐율이 높아 임계값 상향 조정 필요. ";
            }
            
            // 미탐율이 높은 경우
            if (falseNegativeRate > 0.05) {
                adjustments.put("threshold", current.getThreshold() * 0.9);
                adjustments.put("sensitivity", current.getSensitivity() * 1.1);
                rationale += "미탐율이 높아 민감도 상향 조정 필요. ";
            }
            
            // 정밀도와 재현율 균형
            if (precision < 0.8 && recall > 0.9) {
                adjustments.put("specificity", current.getSpecificity() * 1.1);
                rationale += "정밀도 향상을 위한 특이도 조정. ";
            } else if (recall < 0.8 && precision > 0.9) {
                adjustments.put("specificity", current.getSpecificity() * 0.9);
                rationale += "재현율 향상을 위한 특이도 조정. ";
            }
            
            // 예상 개선도 계산
            double expectedImprovement = calculateExpectedImprovement(
                current, adjustments, metrics
            );
            
            return TuningRecommendation.builder()
                .modelId(modelId)
                .parameterAdjustments(adjustments)
                .rationale(rationale)
                .expectedImprovement(expectedImprovement)
                .confidence(calculateConfidence(metrics))
                .build();
        })
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    /**
     * 배치 튜닝 실행
     */
//    @Scheduled(fixedDelayString = "${ai.tuning.evaluation.interval-hours:6}", timeUnit = TimeUnit.HOURS)
    public void performBatchTuning() {
        if (!tuningEnabled) {
            return;
        }
        
        log.info("배치 AI 튜닝 시작");
        totalTuningCycles.incrementAndGet();
        
        learningDataStore.forEach((modelId, data) -> {
            if (data.getSampleCount() >= minSamplesForTuning) {
                performTuning(modelId, data)
                    .subscribe(
                        result -> {
                            if (result.isSuccess()) {
                                successfulTunings.incrementAndGet();
                                log.info("모델 {} 튜닝 성공: {}", modelId, result.getImprovement());
                            }
                        },
                        error -> log.error("모델 {} 튜닝 실패", modelId, error)
                    );
            }
        });
    }
    
    /**
     * 실제 튜닝 수행
     */
    private Mono<LearningResult> performTuning(String modelId, LearningData data) {
        return Mono.fromCallable(() -> {
            ModelParameters current = modelParameters.computeIfAbsent(
                modelId, k -> createDefaultParameters()
            );
            
            // 그래디언트 계산
            Map<String, Double> gradients = calculateGradients(data, current);
            
            // 파라미터 업데이트
            ModelParameters updated = updateParameters(current, gradients);
            
            // 검증
            ValidationResult validation = validateParameters(updated, data);
            
            if (validation.isValid()) {
                // 파라미터 적용
                modelParameters.put(modelId, updated);
                
                // Redis에 저장
                saveParametersToRedis(modelId, updated);
                
                // 히스토리 기록
                recordTuningHistory(modelId, current, updated, validation);
                
                // 성능 메트릭 업데이트
                updatePerformanceMetrics(modelId, validation);
                
                return LearningResult.success(
                    modelId,
                    validation.getImprovement(),
                    updated
                );
            } else {
                return LearningResult.failed(modelId, "Validation failed");
            }
        })
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    /**
     * 그래디언트 계산
     */
    private Map<String, Double> calculateGradients(LearningData data, ModelParameters params) {
        Map<String, Double> gradients = new HashMap<>();
        
        // 손실 함수 기반 그래디언트 계산
        double fpLoss = data.getFalsePositiveCount() * falsePositivePenalty;
        double fnLoss = data.getFalseNegativeCount() * falseNegativePenalty;
        double totalLoss = fpLoss + fnLoss;
        
        // 임계값 그래디언트
        double thresholdGradient = 0.0;
        if (fpLoss > fnLoss) {
            thresholdGradient = learningRate * 0.1;  // 임계값 상향
        } else if (fnLoss > fpLoss) {
            thresholdGradient = -learningRate * 0.1;  // 임계값 하향
        }
        gradients.put("threshold", thresholdGradient);
        
        // 민감도 그래디언트
        double sensitivityGradient = -learningRate * (fpLoss - fnLoss) / totalLoss;
        gradients.put("sensitivity", sensitivityGradient);
        
        // 특이도 그래디언트
        double specificityGradient = learningRate * fpLoss / totalLoss;
        gradients.put("specificity", specificityGradient);
        
        // 학습률 감쇠
        gradients.replaceAll((k, v) -> v * Math.exp(-data.getSampleCount() / 1000.0));
        
        return gradients;
    }
    
    /**
     * 파라미터 업데이트
     */
    private ModelParameters updateParameters(ModelParameters current, Map<String, Double> gradients) {
        ModelParameters updated = current.copy();
        
        // 그래디언트 적용
        updated.setThreshold(
            Math.max(0.1, Math.min(0.99, 
                current.getThreshold() + gradients.getOrDefault("threshold", 0.0)))
        );
        
        updated.setSensitivity(
            Math.max(0.1, Math.min(2.0, 
                current.getSensitivity() + gradients.getOrDefault("sensitivity", 0.0)))
        );
        
        updated.setSpecificity(
            Math.max(0.1, Math.min(2.0, 
                current.getSpecificity() + gradients.getOrDefault("specificity", 0.0)))
        );
        
        // 추가 파라미터 조정
        updated.setWindowSize(current.getWindowSize());  // 유지
        updated.setMinSamples(current.getMinSamples());  // 유지
        updated.setLastUpdated(LocalDateTime.now());
        updated.incrementVersion();
        
        return updated;
    }
    
    /**
     * 파라미터 검증
     */
    private ValidationResult validateParameters(ModelParameters params, LearningData data) {
        // 교차 검증 시뮬레이션
        double estimatedPrecision = simulatePrecision(params, data);
        double estimatedRecall = simulateRecall(params, data);
        double estimatedF1 = 2 * (estimatedPrecision * estimatedRecall) / 
                             (estimatedPrecision + estimatedRecall);
        
        // 현재 성능과 비교
        double currentF1 = data.getCurrentF1Score();
        double improvement = estimatedF1 - currentF1;
        
        boolean valid = estimatedF1 > currentF1 && 
                        estimatedPrecision > 0.7 && 
                        estimatedRecall > 0.7;
        
        return new ValidationResult(valid, improvement, estimatedPrecision, estimatedRecall, estimatedF1);
    }
    
    /**
     * 정밀도 시뮬레이션
     */
    private double simulatePrecision(ModelParameters params, LearningData data) {
        // 간단한 시뮬레이션 (실제로는 더 복잡한 모델 사용)
        double basePrecision = 0.85;
        double adjustment = params.getSpecificity() * 0.1 - params.getSensitivity() * 0.05;
        return Math.max(0.5, Math.min(1.0, basePrecision + adjustment));
    }
    
    /**
     * 재현율 시뮬레이션
     */
    private double simulateRecall(ModelParameters params, LearningData data) {
        // 간단한 시뮬레이션
        double baseRecall = 0.80;
        double adjustment = params.getSensitivity() * 0.1 - params.getThreshold() * 0.05;
        return Math.max(0.5, Math.min(1.0, baseRecall + adjustment));
    }
    
    /**
     * 예상 개선도 계산
     */
    private double calculateExpectedImprovement(
        ModelParameters current,
        Map<String, Double> adjustments,
        PerformanceMetrics metrics
    ) {
        // 간단한 선형 모델로 예상 개선도 계산
        double improvement = 0.0;
        
        for (Map.Entry<String, Double> adj : adjustments.entrySet()) {
            String param = adj.getKey();
            double newValue = adj.getValue();
            double oldValue = getParameterValue(current, param);
            double change = (newValue - oldValue) / oldValue;
            
            // 파라미터별 가중치
            double weight = switch (param) {
                case "threshold" -> 0.4;
                case "sensitivity" -> 0.3;
                case "specificity" -> 0.2;
                default -> 0.1;
            };
            
            improvement += Math.abs(change) * weight;
        }
        
        return Math.min(improvement, 0.3);  // 최대 30% 개선
    }
    
    /**
     * 신뢰도 계산
     */
    private double calculateConfidence(PerformanceMetrics metrics) {
        // 샘플 수와 일관성 기반 신뢰도
        double sampleConfidence = Math.min(1.0, metrics.getSampleCount() / 1000.0);
        double consistencyConfidence = 1.0 - metrics.getVariance();
        
        return (sampleConfidence + consistencyConfidence) / 2;
    }
    
    /**
     * 모델 ID 결정
     */
    private String determineModelId(SecurityEvent event) {
        // 이벤트 타입별 모델 ID
        String type = event.getEventType().name();
        if (type.contains("AUTH")) return "auth_model";
        if (type.contains("NETWORK")) return "network_model";
        if (type.contains("FILE")) return "file_model";
        if (type.contains("PROCESS")) return "process_model";
        return "default_model";
    }
    
    /**
     * 즉시 튜닝 필요 여부
     */
    private boolean shouldTuneImmediately(LearningData data) {
        // 심각한 오탐/미탐 패턴 감지
        return data.getFalsePositiveCount() > 10 || 
               data.getFalseNegativeCount() > 5 ||
               data.getSampleCount() > minSamplesForTuning * 2;
    }
    
    /**
     * 기본 모델 파라미터 초기화
     */
    private void initializeModelParameters() {
        // 각 모델별 기본 파라미터
        String[] modelIds = {"auth_model", "network_model", "file_model", "process_model", "default_model"};
        
        for (String modelId : modelIds) {
            modelParameters.put(modelId, createDefaultParameters());
        }
    }
    
    /**
     * 기본 파라미터 생성
     */
    private ModelParameters createDefaultParameters() {
        return ModelParameters.builder()
            .threshold(0.7)
            .sensitivity(1.0)
            .specificity(1.0)
            .windowSize(60)
            .minSamples(10)
            .lastUpdated(LocalDateTime.now())
            .version(1)
            .build();
    }
    
    /**
     * 기존 학습 데이터 로드
     */
    private void loadExistingLearningData() {
        // Redis에서 기존 학습 데이터 로드
        Set<String> keys = redisTemplate.keys("ai:learning:*");
        if (keys != null) {
            keys.forEach(key -> {
                LearningData data = (LearningData) redisTemplate.opsForValue().get(key);
                if (data != null) {
                    String modelId = key.replace("ai:learning:", "");
                    learningDataStore.put(modelId, data);
                }
            });
            log.info("기존 학습 데이터 {} 개 로드", keys.size());
        }
    }
    
    /**
     * 성능 기준선 설정
     */
    private void establishPerformanceBaseline() {
        // 각 모델의 초기 성능 메트릭 설정
        modelParameters.keySet().forEach(modelId -> {
            PerformanceMetrics baseline = PerformanceMetrics.builder()
                .modelId(modelId)
                .precision(0.85)
                .recall(0.80)
                .f1Score(0.825)
                .falsePositiveRate(0.15)
                .falseNegativeRate(0.20)
                .sampleCount(0)
                .variance(0.05)
                .build();
            
            performanceMetrics.put(modelId, baseline);
        });
    }
    
    /**
     * 오탐 패턴 저장
     */
    private void saveFalsePositivePattern(SecurityEvent event, UserFeedback feedback) {
        Map<String, Object> pattern = new HashMap<>();
        pattern.put("type", "FALSE_POSITIVE");
        pattern.put("eventType", event.getEventType());
        pattern.put("features", extractFeatures(event));
        pattern.put("feedback", feedback);
        pattern.put("timestamp", LocalDateTime.now());
        
        // 벡터 스토어에 저장 - Document 객체로 변환
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("type", "false_positive");
        metadata.put("eventId", event.getEventId());
        metadata.put("timestamp", LocalDateTime.now().toString());
        
        Document doc = new Document(pattern.toString(), metadata);
        vectorStore.addDocuments(List.of(doc));
    }
    
    /**
     * 미탐 패턴 저장
     */
    private void saveFalseNegativePattern(SecurityEvent event, ThreatIndicators indicators) {
        Map<String, Object> pattern = new HashMap<>();
        pattern.put("type", "FALSE_NEGATIVE");
        pattern.put("eventType", event.getEventType());
        pattern.put("features", extractFeatures(event));
        pattern.put("indicators", indicators.toSummary());
        pattern.put("timestamp", LocalDateTime.now());
        
        // 벡터 스토어에 저장 - Document 객체로 변환
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("type", "false_negative");
        metadata.put("eventId", event.getEventId());
        metadata.put("timestamp", LocalDateTime.now().toString());
        
        Document doc = new Document(pattern.toString(), metadata);
        vectorStore.addDocuments(List.of(doc));
    }
    
    /**
     * 특징 추출
     */
    private Map<String, Object> extractFeatures(SecurityEvent event) {
        Map<String, Object> features = new HashMap<>();
        features.put("eventType", event.getEventType());
        features.put("severity", event.getSeverity());
        features.put("source", event.getSource());
        features.put("userId", event.getUserId());
        features.put("ipAddress", event.getSourceIp());
        features.put("timestamp", event.getTimestamp());
        
        // 추가 특징 추출 (실제로는 더 복잡)
        if (event.getMetadata() != null) {
            features.put("dataSize", event.getMetadata().size());
        }
        
        return features;
    }
    
    /**
     * 파라미터를 Redis에 저장
     */
    private void saveParametersToRedis(String modelId, ModelParameters params) {
        String key = "ai:params:" + modelId;
        redisTemplate.opsForValue().set(key, params, Duration.ofDays(7));
    }
    
    /**
     * 튜닝 히스토리 기록
     */
    private void recordTuningHistory(
        String modelId,
        ModelParameters oldParams,
        ModelParameters newParams,
        ValidationResult validation
    ) {
        TuningHistory history = TuningHistory.builder()
            .modelId(modelId)
            .timestamp(LocalDateTime.now())
            .oldParameters(oldParams)
            .newParameters(newParams)
            .improvement(validation.getImprovement())
            .precision(validation.getPrecision())
            .recall(validation.getRecall())
            .f1Score(validation.getF1Score())
            .build();
        
        tuningHistory.add(history);
        
        // 최대 1000개 유지
        if (tuningHistory.size() > 1000) {
            tuningHistory.remove(0);
        }
        
        // Redis에도 저장
        String key = "ai:history:" + modelId + ":" + System.currentTimeMillis();
        redisTemplate.opsForValue().set(key, history, Duration.ofDays(30));
    }
    
    /**
     * 성능 메트릭 업데이트
     */
    private void updatePerformanceMetrics(String modelId, ValidationResult validation) {
        PerformanceMetrics metrics = performanceMetrics.computeIfAbsent(
            modelId, k -> new PerformanceMetrics()
        );
        
        metrics.setPrecision(validation.getPrecision());
        metrics.setRecall(validation.getRecall());
        metrics.setF1Score(validation.getF1Score());
        metrics.setLastUpdated(LocalDateTime.now());
        
        // Redis에 저장
        String key = "ai:metrics:" + modelId;
        redisTemplate.opsForValue().set(key, metrics, Duration.ofDays(7));
    }
    
    /**
     * 파라미터 값 가져오기
     */
    private double getParameterValue(ModelParameters params, String paramName) {
        return switch (paramName) {
            case "threshold" -> params.getThreshold();
            case "sensitivity" -> params.getSensitivity();
            case "specificity" -> params.getSpecificity();
            case "windowSize" -> params.getWindowSize();
            case "minSamples" -> params.getMinSamples();
            default -> 0.0;
        };
    }
    
    /**
     * 인시던트로부터 학습
     *
     * @param incident SOAR 인시던트
     * @param metadata 추가 메타데이터
     * @return 학습 결과
     */
    public Mono<LearningResult> tuneFromIncident(Object incident, Map<String, Object> metadata) {
        if (!tuningEnabled) {
            return Mono.just(LearningResult.disabled());
        }

        return Mono.defer(() -> {
            // 인시던트로부터 학습 데이터 추출
            String modelId = "incident_model";

            // 메타데이터에서 성공/실패 정보 추출
            boolean wasSuccessful = metadata.getOrDefault("successful", false) == Boolean.TRUE;
            String resolution = (String) metadata.getOrDefault("resolution", "UNKNOWN");

            // 학습 데이터 수집
            LearningData data = learningDataStore.computeIfAbsent(modelId, k -> new LearningData());

            if (!wasSuccessful) {
                // 실패한 케이스로부터 학습
                log.info("인시던트 처리 실패로부터 학습: resolution={}", resolution);
                data.sampleCount++;

                // 파라미터 조정이 필요한지 확인
                if (shouldTuneImmediately(data)) {
                    return performTuning(modelId, data);
                }
            } else {
                // 성공한 케이스로부터 강화 학습
                log.debug("인시던트 처리 성공 강화 학습");
                data.currentF1Score = Math.min(1.0, data.currentF1Score * 1.01); // 1% 개선
            }

            return Mono.just(LearningResult.queued(modelId));
        })
        .subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * 메트릭 조회
     */
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("enabled", tuningEnabled);
        metrics.put("totalTuningCycles", totalTuningCycles.get());
        metrics.put("successfulTunings", successfulTunings.get());
        metrics.put("falsePositivesLearned", falsePositivesLearned.get());
        metrics.put("falseNegativesLearned", falseNegativesLearned.get());
        
        Map<String, Map<String, Object>> modelMetrics = new HashMap<>();
        performanceMetrics.forEach((modelId, perf) -> {
            Map<String, Object> m = new HashMap<>();
            m.put("precision", perf.getPrecision());
            m.put("recall", perf.getRecall());
            m.put("f1Score", perf.getF1Score());
            modelMetrics.put(modelId, m);
        });
        metrics.put("modelMetrics", modelMetrics);
        
        metrics.put("historySize", tuningHistory.size());
        
        return metrics;
    }
    
    // 내부 클래스들
    
    /**
     * 학습 데이터
     */
    @lombok.Data
    public static class LearningData {
        private final List<SecurityEvent> falsePositives = new ArrayList<>();
        private final List<SecurityEvent> falseNegatives = new ArrayList<>();
        private final List<UserFeedback> feedbacks = new ArrayList<>();
        private int sampleCount = 0;
        private double currentF1Score = 0.825;  // 기본값
        
        public void addFalsePositive(SecurityEvent event, UserFeedback feedback) {
            falsePositives.add(event);
            feedbacks.add(feedback);
            sampleCount++;
        }
        
        public void addFalseNegative(SecurityEvent event, ThreatIndicators indicators) {
            falseNegatives.add(event);
            sampleCount++;
        }
        
        public int getFalsePositiveCount() {
            return falsePositives.size();
        }
        
        public int getFalseNegativeCount() {
            return falseNegatives.size();
        }
    }
    
    /**
     * 모델 파라미터
     */
    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class ModelParameters {
        private double threshold;
        private double sensitivity;
        private double specificity;
        private int windowSize;
        private int minSamples;
        private LocalDateTime lastUpdated;
        private int version;
        
        public ModelParameters copy() {
            return ModelParameters.builder()
                .threshold(threshold)
                .sensitivity(sensitivity)
                .specificity(specificity)
                .windowSize(windowSize)
                .minSamples(minSamples)
                .lastUpdated(lastUpdated)
                .version(version)
                .build();
        }
        
        public void incrementVersion() {
            version++;
        }
    }
    
    /**
     * 성능 메트릭
     */
    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class PerformanceMetrics {
        private String modelId;
        private double precision;
        private double recall;
        private double f1Score;
        private double falsePositiveRate;
        private double falseNegativeRate;
        private int sampleCount;
        private double variance;
        private LocalDateTime lastUpdated;
    }
    
    /**
     * 학습 결과
     */
    @lombok.Data
    @lombok.Builder
    public static class LearningResult {
        private boolean success;
        private String modelId;
        private double improvement;
        private ModelParameters updatedParameters;
        private String message;
        
        public static LearningResult disabled() {
            return LearningResult.builder()
                .success(false)
                .message("Tuning disabled")
                .build();
        }
        
        public static LearningResult queued(String modelId) {
            return LearningResult.builder()
                .success(true)
                .modelId(modelId)
                .message("Queued for batch tuning")
                .build();
        }
        
        public static LearningResult success(String modelId, double improvement, ModelParameters params) {
            return LearningResult.builder()
                .success(true)
                .modelId(modelId)
                .improvement(improvement)
                .updatedParameters(params)
                .message("Tuning successful")
                .build();
        }
        
        public static LearningResult failed(String modelId, String reason) {
            return LearningResult.builder()
                .success(false)
                .modelId(modelId)
                .message(reason)
                .build();
        }
    }
    
    /**
     * 튜닝 제안
     */
    @lombok.Data
    @lombok.Builder
    public static class TuningRecommendation {
        private String modelId;
        private Map<String, Double> parameterAdjustments;
        private String rationale;
        private double expectedImprovement;
        private double confidence;
        
        public static TuningRecommendation noRecommendation() {
            return TuningRecommendation.builder()
                .rationale("No tuning needed")
                .expectedImprovement(0.0)
                .confidence(0.0)
                .build();
        }
    }
    
    /**
     * 사용자 피드백
     */
    @lombok.Data
    @lombok.Builder
    public static class UserFeedback {
        private String userId;
        private String feedbackType;  // FALSE_POSITIVE, FALSE_NEGATIVE, CORRECT
        private String comment;
        private LocalDateTime timestamp;
    }
    
    /**
     * 검증 결과
     */
    @lombok.Data
    @lombok.AllArgsConstructor
    private static class ValidationResult {
        private boolean valid;
        private double improvement;
        private double precision;
        private double recall;
        private double f1Score;
    }
    
    /**
     * 튜닝 히스토리
     */
    @lombok.Data
    @lombok.Builder
    private static class TuningHistory {
        private String modelId;
        private LocalDateTime timestamp;
        private ModelParameters oldParameters;
        private ModelParameters newParameters;
        private double improvement;
        private double precision;
        private double recall;
        private double f1Score;
    }
}