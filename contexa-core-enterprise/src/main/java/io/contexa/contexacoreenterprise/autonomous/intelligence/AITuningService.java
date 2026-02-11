package io.contexa.contexacoreenterprise.autonomous.intelligence;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatIndicators;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.VectorStore;
import io.contexa.contexacoreenterprise.properties.AiTuningProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

@Slf4j
@RequiredArgsConstructor
public class AITuningService {

    private final VectorStore vectorStore;
    private final RedisTemplate<String, Object> redisTemplate;
    private final AiTuningProperties aiTuningProperties;

    private final Map<String, LearningData> learningDataStore = new ConcurrentHashMap<>();

    private final Map<String, ModelParameters> modelParameters = new ConcurrentHashMap<>();

    private final Map<String, PerformanceMetrics> performanceMetrics = new ConcurrentHashMap<>();

    private final List<TuningHistory> tuningHistory = Collections.synchronizedList(new ArrayList<>());

    private final AtomicLong totalTuningCycles = new AtomicLong(0);
    private final AtomicLong successfulTunings = new AtomicLong(0);
    private final AtomicLong falsePositivesLearned = new AtomicLong(0);
    private final AtomicLong falseNegativesLearned = new AtomicLong(0);
    
    @PostConstruct
    public void initialize() {
        if (!aiTuningProperties.isEnabled()) {
                        return;
        }

        initializeModelParameters();

        loadExistingLearningData();

        establishPerformanceBaseline();
        
            }

    public Mono<LearningResult> learnFalsePositive(SecurityEvent event, UserFeedback feedback) {
        if (!aiTuningProperties.isEnabled()) {
            return Mono.just(LearningResult.disabled());
        }
        
        return Mono.defer(() -> {
            String modelId = determineModelId(event);

            LearningData data = learningDataStore.computeIfAbsent(modelId, k -> new LearningData());
            data.addFalsePositive(event, feedback);
            falsePositivesLearned.incrementAndGet();

            saveFalsePositivePattern(event, feedback);

            if (shouldTuneImmediately(data)) {
                return performTuning(modelId, data);
            }
            
            return Mono.just(LearningResult.queued(modelId));
        })
        .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<LearningResult> learnFalseNegative(SecurityEvent missedEvent, ThreatIndicators indicators) {
        if (!aiTuningProperties.isEnabled()) {
            return Mono.just(LearningResult.disabled());
        }
        
        return Mono.defer(() -> {
            String modelId = determineModelId(missedEvent);

            LearningData data = learningDataStore.computeIfAbsent(modelId, k -> new LearningData());
            data.addFalseNegative(missedEvent, indicators);
            falseNegativesLearned.incrementAndGet();

            saveFalseNegativePattern(missedEvent, indicators);

            if (shouldTuneImmediately(data)) {
                return performTuning(modelId, data);
            }
            
            return Mono.just(LearningResult.queued(modelId));
        })
        .subscribeOn(Schedulers.boundedElastic());
    }

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

            double falsePositiveRate = metrics.getFalsePositiveRate();
            double falseNegativeRate = metrics.getFalseNegativeRate();
            double precision = metrics.getPrecision();
            double recall = metrics.getRecall();
            double f1Score = metrics.getF1Score();
            
            Map<String, Double> adjustments = new HashMap<>();
            String rationale = "";

            if (falsePositiveRate > 0.1) {
                adjustments.put("threshold", current.getThreshold() * 1.1);
                adjustments.put("sensitivity", current.getSensitivity() * 0.9);
                rationale += "오탐율이 높아 임계값 상향 조정 필요. ";
            }

            if (falseNegativeRate > 0.05) {
                adjustments.put("threshold", current.getThreshold() * 0.9);
                adjustments.put("sensitivity", current.getSensitivity() * 1.1);
                rationale += "미탐율이 높아 민감도 상향 조정 필요. ";
            }

            if (precision < 0.8 && recall > 0.9) {
                adjustments.put("specificity", current.getSpecificity() * 1.1);
                rationale += "정밀도 향상을 위한 특이도 조정. ";
            } else if (recall < 0.8 && precision > 0.9) {
                adjustments.put("specificity", current.getSpecificity() * 0.9);
                rationale += "재현율 향상을 위한 특이도 조정. ";
            }

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

    public void performBatchTuning() {
        if (!aiTuningProperties.isEnabled()) {
            return;
        }
        
                totalTuningCycles.incrementAndGet();
        
        learningDataStore.forEach((modelId, data) -> {
            if (data.getSampleCount() >= aiTuningProperties.getMin().getSamples()) {
                performTuning(modelId, data)
                    .subscribe(
                        result -> {
                            if (result.isSuccess()) {
                                successfulTunings.incrementAndGet();
                                                            }
                        },
                        error -> log.error("모델 {} 튜닝 실패", modelId, error)
                    );
            }
        });
    }

    private Mono<LearningResult> performTuning(String modelId, LearningData data) {
        return Mono.fromCallable(() -> {
            ModelParameters current = modelParameters.computeIfAbsent(
                modelId, k -> createDefaultParameters()
            );

            Map<String, Double> gradients = calculateGradients(data, current);

            ModelParameters updated = updateParameters(current, gradients);

            ValidationResult validation = validateParameters(updated, data);
            
            if (validation.isValid()) {
                
                modelParameters.put(modelId, updated);

                saveParametersToRedis(modelId, updated);

                recordTuningHistory(modelId, current, updated, validation);

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

    private Map<String, Double> calculateGradients(LearningData data, ModelParameters params) {
        Map<String, Double> gradients = new HashMap<>();

        double fpLoss = data.getFalsePositiveCount() * aiTuningProperties.getFalsePositive().getPenalty();
        double fnLoss = data.getFalseNegativeCount() * aiTuningProperties.getFalseNegative().getPenalty();
        double totalLoss = fpLoss + fnLoss;

        double thresholdGradient = 0.0;
        if (fpLoss > fnLoss) {
            thresholdGradient = aiTuningProperties.getLearning().getRate() * 0.1;  
        } else if (fnLoss > fpLoss) {
            thresholdGradient = -aiTuningProperties.getLearning().getRate() * 0.1;  
        }
        gradients.put("threshold", thresholdGradient);

        double sensitivityGradient = -aiTuningProperties.getLearning().getRate() * (fpLoss - fnLoss) / totalLoss;
        gradients.put("sensitivity", sensitivityGradient);

        double specificityGradient = aiTuningProperties.getLearning().getRate() * fpLoss / totalLoss;
        gradients.put("specificity", specificityGradient);

        gradients.replaceAll((k, v) -> v * Math.exp(-data.getSampleCount() / 1000.0));
        
        return gradients;
    }

    private ModelParameters updateParameters(ModelParameters current, Map<String, Double> gradients) {
        ModelParameters updated = current.copy();

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

        updated.setWindowSize(current.getWindowSize());  
        updated.setMinSamples(current.getMinSamples());  
        updated.setLastUpdated(LocalDateTime.now());
        updated.incrementVersion();
        
        return updated;
    }

    private ValidationResult validateParameters(ModelParameters params, LearningData data) {
        
        double estimatedPrecision = simulatePrecision(params, data);
        double estimatedRecall = simulateRecall(params, data);
        double estimatedF1 = 2 * (estimatedPrecision * estimatedRecall) / 
                             (estimatedPrecision + estimatedRecall);

        double currentF1 = data.getCurrentF1Score();
        double improvement = estimatedF1 - currentF1;
        
        boolean valid = estimatedF1 > currentF1 && 
                        estimatedPrecision > 0.7 && 
                        estimatedRecall > 0.7;
        
        return new ValidationResult(valid, improvement, estimatedPrecision, estimatedRecall, estimatedF1);
    }

    private double simulatePrecision(ModelParameters params, LearningData data) {
        
        double basePrecision = 0.85;
        double adjustment = params.getSpecificity() * 0.1 - params.getSensitivity() * 0.05;
        return Math.max(0.5, Math.min(1.0, basePrecision + adjustment));
    }

    private double simulateRecall(ModelParameters params, LearningData data) {
        
        double baseRecall = 0.80;
        double adjustment = params.getSensitivity() * 0.1 - params.getThreshold() * 0.05;
        return Math.max(0.5, Math.min(1.0, baseRecall + adjustment));
    }

    private double calculateExpectedImprovement(
        ModelParameters current,
        Map<String, Double> adjustments,
        PerformanceMetrics metrics
    ) {
        
        double improvement = 0.0;
        
        for (Map.Entry<String, Double> adj : adjustments.entrySet()) {
            String param = adj.getKey();
            double newValue = adj.getValue();
            double oldValue = getParameterValue(current, param);
            double change = (newValue - oldValue) / oldValue;

            double weight = switch (param) {
                case "threshold" -> 0.4;
                case "sensitivity" -> 0.3;
                case "specificity" -> 0.2;
                default -> 0.1;
            };
            
            improvement += Math.abs(change) * weight;
        }
        
        return Math.min(improvement, 0.3);  
    }

    private double calculateConfidence(PerformanceMetrics metrics) {
        
        double sampleConfidence = Math.min(1.0, metrics.getSampleCount() / 1000.0);
        double consistencyConfidence = 1.0 - metrics.getVariance();
        
        return (sampleConfidence + consistencyConfidence) / 2;
    }

    private String determineModelId(SecurityEvent event) {
        
        String source = event.getSource() != null ? event.getSource().name() : "UNKNOWN";
        return switch (source) {
            case "IAM" -> "auth_model";
            case "NETWORK" -> "network_model";
            case "ENDPOINT" -> "file_model";
            case "CLOUD" -> "cloud_model";
            default -> "default_model";
        };
    }

    private boolean shouldTuneImmediately(LearningData data) {
        
        return data.getFalsePositiveCount() > 10 || 
               data.getFalseNegativeCount() > 5 ||
               data.getSampleCount() > aiTuningProperties.getMin().getSamples() * 2;
    }

    private void initializeModelParameters() {
        
        String[] modelIds = {"auth_model", "network_model", "file_model", "process_model", "default_model"};
        
        for (String modelId : modelIds) {
            modelParameters.put(modelId, createDefaultParameters());
        }
    }

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

    private void loadExistingLearningData() {
        
        Set<String> keys = redisTemplate.keys("ai:learning:*");
        if (keys != null) {
            keys.forEach(key -> {
                LearningData data = (LearningData) redisTemplate.opsForValue().get(key);
                if (data != null) {
                    String modelId = key.replace("ai:learning:", "");
                    learningDataStore.put(modelId, data);
                }
            });
                    }
    }

    private void establishPerformanceBaseline() {
        
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

    private void saveFalsePositivePattern(SecurityEvent event, UserFeedback feedback) {
        Map<String, Object> pattern = new HashMap<>();
        pattern.put("type", "FALSE_POSITIVE");
        pattern.put("severity", event.getSeverity());
        pattern.put("features", extractFeatures(event));
        pattern.put("feedback", feedback);
        pattern.put("timestamp", LocalDateTime.now());

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("type", "false_positive");
        metadata.put("eventId", event.getEventId());
        metadata.put("timestamp", LocalDateTime.now().toString());
        
        Document doc = new Document(pattern.toString(), metadata);
        vectorStore.add(List.of(doc));
    }

    private void saveFalseNegativePattern(SecurityEvent event, ThreatIndicators indicators) {
        Map<String, Object> pattern = new HashMap<>();
        pattern.put("type", "FALSE_NEGATIVE");
        pattern.put("severity", event.getSeverity());
        pattern.put("features", extractFeatures(event));
        pattern.put("indicators", indicators.toSummary());
        pattern.put("timestamp", LocalDateTime.now());

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("type", "false_negative");
        metadata.put("eventId", event.getEventId());
        metadata.put("timestamp", LocalDateTime.now().toString());
        
        Document doc = new Document(pattern.toString(), metadata);
        vectorStore.add(List.of(doc));
    }

    private Map<String, Object> extractFeatures(SecurityEvent event) {
        Map<String, Object> features = new HashMap<>();
        features.put("severity", event.getSeverity());
        features.put("source", event.getSource());
        features.put("userId", event.getUserId());
        features.put("ipAddress", event.getSourceIp());
        features.put("timestamp", event.getTimestamp());

        if (event.getMetadata() != null) {
            features.put("dataSize", event.getMetadata().size());
        }
        
        return features;
    }

    private void saveParametersToRedis(String modelId, ModelParameters params) {
        String key = "ai:params:" + modelId;
        redisTemplate.opsForValue().set(key, params, Duration.ofDays(7));
    }

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

        if (tuningHistory.size() > 1000) {
            tuningHistory.remove(0);
        }

        String key = "ai:history:" + modelId + ":" + System.currentTimeMillis();
        redisTemplate.opsForValue().set(key, history, Duration.ofDays(30));
    }

    private void updatePerformanceMetrics(String modelId, ValidationResult validation) {
        PerformanceMetrics metrics = performanceMetrics.computeIfAbsent(
            modelId, k -> new PerformanceMetrics()
        );
        
        metrics.setPrecision(validation.getPrecision());
        metrics.setRecall(validation.getRecall());
        metrics.setF1Score(validation.getF1Score());
        metrics.setLastUpdated(LocalDateTime.now());

        String key = "ai:metrics:" + modelId;
        redisTemplate.opsForValue().set(key, metrics, Duration.ofDays(7));
    }

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

    public Mono<LearningResult> tuneFromIncident(Object incident, Map<String, Object> metadata) {
        if (!aiTuningProperties.isEnabled()) {
            return Mono.just(LearningResult.disabled());
        }

        return Mono.defer(() -> {
            
            String modelId = "incident_model";

            boolean wasSuccessful = metadata.getOrDefault("successful", false) == Boolean.TRUE;
            String resolution = (String) metadata.getOrDefault("resolution", "UNKNOWN");

            LearningData data = learningDataStore.computeIfAbsent(modelId, k -> new LearningData());

            if (!wasSuccessful) {
                
                                data.sampleCount++;

                if (shouldTuneImmediately(data)) {
                    return performTuning(modelId, data);
                }
            } else {
                
                                data.currentF1Score = Math.min(1.0, data.currentF1Score * 1.01); 
            }

            return Mono.just(LearningResult.queued(modelId));
        })
        .subscribeOn(Schedulers.boundedElastic());
    }

    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("enabled", aiTuningProperties.isEnabled());
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

    @lombok.Data
    public static class LearningData {
        private final List<SecurityEvent> falsePositives = new ArrayList<>();
        private final List<SecurityEvent> falseNegatives = new ArrayList<>();
        private final List<UserFeedback> feedbacks = new ArrayList<>();
        private int sampleCount = 0;
        private double currentF1Score = 0.825;  
        
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

    @lombok.Data
    @lombok.Builder
    public static class UserFeedback {
        private String userId;
        private String feedbackType;  
        private String comment;
        private LocalDateTime timestamp;
    }

    @lombok.Data
    @lombok.AllArgsConstructor
    private static class ValidationResult {
        private boolean valid;
        private double improvement;
        private double precision;
        private double recall;
        private double f1Score;
    }

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