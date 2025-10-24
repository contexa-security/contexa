package io.contexa.contexacore.simulation.strategy.impl;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.client.SimulationClient;
import io.contexa.contexacore.simulation.strategy.IAIMLAttack;
import io.contexa.contexacore.simulation.publisher.SimulationEventPublisher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Adversarial Evasion Attack 전략
 *
 * AI/ML 모델의 탐지를 회피하는 적대적 예제 생성
 */
@Slf4j
@Component
public class AdversarialEvasionStrategy implements IAIMLAttack {

    private SimulationEventPublisher eventPublisher;

    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Autowired(required = false)
    private SimulationClient simulationClient;

    @Value("${simulation.attack.adversarial.epsilon:0.1}")
    private double epsilon; // Perturbation 크기

    @Value("${simulation.attack.adversarial.iterations:100}")
    private int maxIterations;

    private final ExecutorService executor = Executors.newFixedThreadPool(5);

    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.ADVERSARIAL_EVASION;
    }

    @Override
    public int getPriority() {
        return 85;
    }

    @Override
    public AttackCategory getCategory() {
        return AttackCategory.AI_ML;
    }

    @Override
    public boolean validateContext(AttackContext context) {
        return context != null && context.getParameters() != null;
    }

    @Override
    public long getEstimatedDuration() {
        return maxIterations * 500L;
    }

    @Override
    public String getDescription() {
        return "Adversarial Evasion Attack - Creates adversarial examples to evade detection";
    }

    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.MEDIUM;
    }

    @Override
    public String getSuccessCriteria() {
        return "Successfully generate adversarial examples that evade model detection";
    }

    @Override
    public AttackResult execute(AttackContext context) {
        log.warn("=== Adversarial Evasion Attack 시작 ===");

        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .campaignId(context.getCampaignId())
            .type(AttackResult.AttackType.ADVERSARIAL_EVASION)
            .attackName("Adversarial Evasion Attack")
            .executionTime(LocalDateTime.now())
            .targetUser(context.getTargetUser())
            .attackVector("ai-ml")
            .build();

        long startTime = System.currentTimeMillis();
        List<String> attackLog = new ArrayList<>();

        try {
            // 1. 공격 매개변수 추출
            String targetModel = context.getParameters().getOrDefault("targetModel", "threat_detector").toString();
            String evasionMethod = context.getParameters().getOrDefault("evasionMethod", "FGSM").toString();
            String targetClass = context.getParameters().getOrDefault("targetClass", "benign").toString();
            int samples = Integer.parseInt(
                context.getParameters().getOrDefault("samples", "10").toString()
            );

            attackLog.add("Target model: " + targetModel);
            attackLog.add("Evasion method: " + evasionMethod);
            attackLog.add("Target misclassification: " + targetClass);
            attackLog.add("Adversarial samples: " + samples);

            // 2. 적대적 예제 생성
            List<AdversarialSample> adversarialSamples = generateAdversarialExamples(
                evasionMethod, targetModel, targetClass, samples
            );
            attackLog.add("Generated " + adversarialSamples.size() + " adversarial examples");

            // 3. 회피 공격 실행
            int successfulEvasions = 0;
            int detectedSamples = 0;
            List<String> evadedModels = new ArrayList<>();

            for (AdversarialSample sample : adversarialSamples) {
                EvasionResult evasionResult = executeEvasion(sample, targetModel);

                if (evasionResult.evaded) {
                    successfulEvasions++;
                    if (!evadedModels.contains(evasionResult.model)) {
                        evadedModels.add(evasionResult.model);
                    }
                    attackLog.add("[SUCCESS] Evaded " + evasionResult.model +
                        " with confidence " + evasionResult.confidence);
                } else if (evasionResult.detected) {
                    detectedSamples++;
                    attackLog.add("[DETECTED] Sample detected by " + evasionResult.model);
                }
            }

            // 4. 전이성 테스트 (Transferability)
            boolean transferable = testTransferability(adversarialSamples, attackLog);
            if (transferable) {
                attackLog.add("Adversarial examples are transferable across models");
            }

            // 5. 강건성 평가
            double robustness = evaluateRobustness(adversarialSamples, targetModel);
            attackLog.add("Adversarial robustness score: " + robustness);

            // 6. 결과 평가
            double evasionRate = (double) successfulEvasions / samples;

            if (evasionRate > 0.3) {
                result.setSuccessful(true);
                result.setRiskScore(Math.min(1.0, 0.4 + evasionRate * 0.5));
                attackLog.add("Adversarial evasion successful - " +
                    (evasionRate * 100) + "% evasion rate");
            } else {
                result.setSuccessful(false);
                result.setRiskScore(0.3);
                attackLog.add("Adversarial evasion failed - model is robust");
            }

            // 탐지 평가
            result.setDetected(detectedSamples > samples * 0.5);
            result.setBlocked(successfulEvasions == 0);

            result.setDetails(Map.of(
                "attackLog", attackLog,
                "targetModel", targetModel,
                "evasionMethod", evasionMethod,
                "totalSamples", samples,
                "successfulEvasions", successfulEvasions,
                "evasionRate", evasionRate,
                "evadedModels", evadedModels,
                "transferable", transferable,
                "robustness", robustness
            ));

        } catch (Exception e) {
            log.error("Adversarial evasion attack failed", e);
            result.setSuccessful(false);
            result.setRiskScore(0.1);
            attackLog.add("Attack failed: " + e.getMessage());
        }

        long duration = System.currentTimeMillis() - startTime;
        result.setDurationMs(duration);

        log.info("Adversarial Evasion Attack 완료: Success={}, Risk={}, Duration={}ms",
            result.isSuccessful(), result.getRiskScore(), duration);

        // 이벤트 발행 - 적대적 회피 공격은 인가 결정 이벤트로 처리
        if (eventPublisher != null) {
            String resource = "aiml:detection:" + context.getParameters().getOrDefault("targetModel", "threat_detector");
            String action = "ADVERSARIAL_EVASION_" + context.getParameters().getOrDefault("evasionMethod", "FGSM");
            eventPublisher.publishAuthorizationDecision(
                result,
                context.getTargetUser(),
                resource,
                action,
                result.isSuccessful(),
                result.isSuccessful() ?
                    "적대적 회피 공격 성공: " + context.getParameters().getOrDefault("evasionMethod", "FGSM") + " 기법으로 " +
                    result.getDetails().get("successfulEvasions") + "개 샘플 회피, " +
                    "회피율 " + String.format("%.1f%%", ((Number)result.getDetails().get("evasionRate")).doubleValue() * 100) + " 달성" +
                    (Boolean.TRUE.equals(result.getDetails().get("transferable")) ? ", 전이성 확인됨" : "") :
                    "적대적 회피 공격 실패: 모델이 견고하게 보호됨"
            );
        }

        return result;
    }

    private List<AdversarialSample> generateAdversarialExamples(
        String method, String model, String targetClass, int count) {

        List<AdversarialSample> samples = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            AdversarialSample sample = new AdversarialSample();
            sample.id = UUID.randomUUID().toString();
            sample.targetModel = model;
            sample.targetClass = targetClass;

            // 원본 악성 샘플
            sample.originalFeatures = generateMaliciousFeatures();
            sample.originalClass = "malicious";

            switch (method) {
                case "FGSM": // Fast Gradient Sign Method
                    sample.perturbedFeatures = applyFGSM(sample.originalFeatures);
                    sample.method = "FGSM";
                    sample.epsilon = epsilon;
                    break;

                case "PGD": // Projected Gradient Descent
                    sample.perturbedFeatures = applyPGD(sample.originalFeatures);
                    sample.method = "PGD";
                    sample.epsilon = epsilon;
                    sample.iterations = 10;
                    break;

                case "CW": // Carlini-Wagner
                    sample.perturbedFeatures = applyCW(sample.originalFeatures);
                    sample.method = "C&W";
                    sample.confidence = 0.9;
                    break;

                case "DEEPFOOL":
                    sample.perturbedFeatures = applyDeepFool(sample.originalFeatures);
                    sample.method = "DeepFool";
                    sample.overshoot = 0.02;
                    break;

                case "JSMA": // Jacobian-based Saliency Map Attack
                    sample.perturbedFeatures = applyJSMA(sample.originalFeatures);
                    sample.method = "JSMA";
                    sample.maxPixels = 100;
                    break;

                case "EVOLUTIONARY":
                    sample.perturbedFeatures = applyEvolutionary(sample.originalFeatures);
                    sample.method = "Evolutionary";
                    sample.generations = 50;
                    break;

                case "FEATURE_SQUEEZING":
                    sample.perturbedFeatures = applyFeatureSqueezing(sample.originalFeatures);
                    sample.method = "Feature Squeezing";
                    sample.bitDepth = 4;
                    break;

                default:
                    sample.perturbedFeatures = applyRandomNoise(sample.originalFeatures);
                    sample.method = "Random Noise";
                    sample.noiseLevel = 0.1;
                    break;
            }

            samples.add(sample);
        }

        return samples;
    }

    private Map<String, Object> generateMaliciousFeatures() {
        Map<String, Object> features = new HashMap<>();

        // 악성 행동 특징 - 실제 공격 패턴에 기반
        long featureSeed = System.currentTimeMillis();
        features.put("request_rate", 500 + (featureSeed % 1000));
        features.put("failed_logins", 10 + (int)(featureSeed % 50));
        features.put("data_exfiltration", (double)(featureSeed % 100));
        features.put("privilege_escalation_attempts", (int)(featureSeed % 20));
        features.put("anomaly_score", 0.7 + ((featureSeed % 30) / 100.0));
        features.put("suspicious_commands", Arrays.asList("sudo", "chmod", "nc"));
        features.put("network_scanning", true);
        features.put("payload_entropy", 0.9 + ((featureSeed % 10) / 100.0));

        return features;
    }

    private Map<String, Object> applyFGSM(Map<String, Object> features) {
        // Fast Gradient Sign Method
        Map<String, Object> perturbed = new HashMap<>(features);

        for (Map.Entry<String, Object> entry : perturbed.entrySet()) {
            if (entry.getValue() instanceof Number) {
                double value = ((Number) entry.getValue()).doubleValue();
                double gradient = calculateGradient(entry.getKey(), value);
                double perturbation = epsilon * Math.signum(gradient);
                perturbed.put(entry.getKey(), value + perturbation);
            }
        }

        return normalizeFeatures(perturbed);
    }

    private Map<String, Object> applyPGD(Map<String, Object> features) {
        // Projected Gradient Descent
        Map<String, Object> perturbed = new HashMap<>(features);

        for (int iter = 0; iter < 10; iter++) {
            for (Map.Entry<String, Object> entry : perturbed.entrySet()) {
                if (entry.getValue() instanceof Number) {
                    double value = ((Number) entry.getValue()).doubleValue();
                    double gradient = calculateGradient(entry.getKey(), value);
                    double step = epsilon / 10.0;
                    value = value + step * gradient;

                    // Project back to epsilon ball
                    double original = ((Number) features.get(entry.getKey())).doubleValue();
                    value = Math.max(original - epsilon, Math.min(original + epsilon, value));
                    perturbed.put(entry.getKey(), value);
                }
            }
        }

        return normalizeFeatures(perturbed);
    }

    private Map<String, Object> applyCW(Map<String, Object> features) {
        // Carlini-Wagner attack
        Map<String, Object> perturbed = new HashMap<>(features);

        // Minimize L2 norm while ensuring misclassification
        double confidence = 0.9;

        for (Map.Entry<String, Object> entry : perturbed.entrySet()) {
            if (entry.getValue() instanceof Number) {
                double value = ((Number) entry.getValue()).doubleValue();
                // Optimize for minimal perturbation with high confidence
                double optimalPerturbation = findOptimalPerturbation(entry.getKey(), value, confidence);
                perturbed.put(entry.getKey(), value + optimalPerturbation);
            }
        }

        return normalizeFeatures(perturbed);
    }

    private Map<String, Object> applyDeepFool(Map<String, Object> features) {
        // DeepFool: minimal perturbation to cross decision boundary
        Map<String, Object> perturbed = new HashMap<>(features);

        // Find minimal perturbation to nearest class boundary
        for (Map.Entry<String, Object> entry : perturbed.entrySet()) {
            if (entry.getValue() instanceof Number) {
                double value = ((Number) entry.getValue()).doubleValue();
                double boundary = findNearestBoundary(entry.getKey(), value);
                double perturbation = (boundary - value) * 1.02; // 2% overshoot
                perturbed.put(entry.getKey(), value + perturbation);
            }
        }

        return normalizeFeatures(perturbed);
    }

    private Map<String, Object> applyJSMA(Map<String, Object> features) {
        // Jacobian-based Saliency Map Attack
        Map<String, Object> perturbed = new HashMap<>(features);

        // Find most salient features to modify
        List<String> salientFeatures = findSalientFeatures(features, 5);

        for (String feature : salientFeatures) {
            if (perturbed.get(feature) instanceof Number) {
                double value = ((Number) perturbed.get(feature)).doubleValue();
                // Modify salient features maximally
                perturbed.put(feature, value * 0.1); // Reduce to appear benign
            }
        }

        return normalizeFeatures(perturbed);
    }

    private Map<String, Object> applyEvolutionary(Map<String, Object> features) {
        // Evolutionary/Genetic algorithm approach
        Map<String, Object> perturbed = new HashMap<>(features);

        // Evolve perturbation over generations
        for (int gen = 0; gen < 50; gen++) {
            Map<String, Object> candidate = mutateSample(perturbed);
            if (evaluateFitness(candidate) > evaluateFitness(perturbed)) {
                perturbed = candidate;
            }
        }

        return normalizeFeatures(perturbed);
    }

    private Map<String, Object> applyFeatureSqueezing(Map<String, Object> features) {
        // Reduce feature precision to evade detection
        Map<String, Object> perturbed = new HashMap<>(features);

        for (Map.Entry<String, Object> entry : perturbed.entrySet()) {
            if (entry.getValue() instanceof Number) {
                double value = ((Number) entry.getValue()).doubleValue();
                // Reduce bit depth
                int quantized = (int) (value * 16) / 16;
                perturbed.put(entry.getKey(), (double) quantized);
            }
        }

        return perturbed;
    }

    private Map<String, Object> applyRandomNoise(Map<String, Object> features) {
        // Simple random noise addition
        Map<String, Object> perturbed = new HashMap<>(features);

        for (Map.Entry<String, Object> entry : perturbed.entrySet()) {
            if (entry.getValue() instanceof Number) {
                double value = ((Number) entry.getValue()).doubleValue();
                // 결정론적 노이즈 추가
                long noiseSeed = System.nanoTime();
                double noise = ((noiseSeed % 1000) / 1000.0 - 0.5) * 0.2;
                perturbed.put(entry.getKey(), value + noise);
            }
        }

        return normalizeFeatures(perturbed);
    }

    private double calculateGradient(String feature, double value) {
        // Simulate gradient calculation
        // 결정론적 gradient 계산
        long gradientSeed = System.nanoTime();
        return ((gradientSeed % 1000) / 500.0 - 1.0);
    }

    private double findOptimalPerturbation(String feature, double value, double confidence) {
        // Binary search for optimal perturbation
        double low = -epsilon, high = epsilon;

        for (int i = 0; i < 10; i++) {
            double mid = (low + high) / 2;
            if (evaluateConfidence(feature, value + mid) > confidence) {
                high = mid;
            } else {
                low = mid;
            }
        }

        return (low + high) / 2;
    }

    private double findNearestBoundary(String feature, double value) {
        // Find nearest decision boundary
        return value * 0.5; // Simplified: move halfway to benign range
    }

    private List<String> findSalientFeatures(Map<String, Object> features, int count) {
        // Find most important features for classification
        List<String> allFeatures = new ArrayList<>(features.keySet());
        Collections.shuffle(allFeatures);
        return allFeatures.stream()
            .filter(f -> features.get(f) instanceof Number)
            .limit(count)
            .collect(Collectors.toList());
    }

    private Map<String, Object> mutateSample(Map<String, Object> sample) {
        Map<String, Object> mutated = new HashMap<>(sample);
        // 결정론적 feature 선택
        long featureSelectSeed = System.nanoTime();
        String randomFeature = new ArrayList<>(sample.keySet()).get((int)(featureSelectSeed % sample.size()));

        if (mutated.get(randomFeature) instanceof Number) {
            double value = ((Number) mutated.get(randomFeature)).doubleValue();
            // 결정론적 부동 소수점 변이
            long mutationSeed = System.nanoTime();
            mutated.put(randomFeature, value + ((mutationSeed % 1000) / 1000.0 - 0.5) * 0.1);
        }

        return mutated;
    }

    private double evaluateFitness(Map<String, Object> sample) {
        // Fitness function for evolutionary algorithm
        double benignScore = 0;

        if (sample.get("request_rate") instanceof Number) {
            double rate = ((Number) sample.get("request_rate")).doubleValue();
            if (rate < 100) benignScore += 0.3;
        }

        if (sample.get("failed_logins") instanceof Number) {
            double fails = ((Number) sample.get("failed_logins")).doubleValue();
            if (fails < 3) benignScore += 0.3;
        }

        if (sample.get("anomaly_score") instanceof Number) {
            double score = ((Number) sample.get("anomaly_score")).doubleValue();
            if (score < 0.3) benignScore += 0.4;
        }

        return benignScore;
    }

    private double evaluateConfidence(String feature, double value) {
        // Evaluate model confidence for given feature value
        return Math.abs(value) / 100.0;
    }

    private Map<String, Object> normalizeFeatures(Map<String, Object> features) {
        // Normalize features to valid ranges
        Map<String, Object> normalized = new HashMap<>(features);

        for (Map.Entry<String, Object> entry : normalized.entrySet()) {
            if (entry.getValue() instanceof Number) {
                double value = ((Number) entry.getValue()).doubleValue();
                value = Math.max(0, value); // Ensure non-negative
                normalized.put(entry.getKey(), value);
            }
        }

        return normalized;
    }

    private EvasionResult executeEvasion(AdversarialSample sample, String targetModel) {
        EvasionResult result = new EvasionResult();
        result.model = targetModel;

        if (simulationClient != null) {
            try {
                Map<String, Object> params = Map.of(
                    "model", targetModel,
                    "features", sample.perturbedFeatures,
                    "expected_class", sample.targetClass
                );

                ResponseEntity<String> response = simulationClient.executeAttack(
                    "/api/ml/classify", params
                );

                if (response.getStatusCode().is2xxSuccessful() &&
                    response.getBody() != null &&
                    response.getBody().contains(sample.targetClass)) {
                    result.evaded = true;
                    result.confidence = 0.8;
                } else {
                    result.detected = true;
                }
            } catch (Exception e) {
                result.error = e.getMessage();
            }
        } else {
            // 시뮬레이션 모드
            double evasionChance = evaluateFitness(sample.perturbedFeatures);
            result.evaded = evasionChance > 0.5;
            // 결정론적 탐지 여부 판단
            long detectSeed = System.currentTimeMillis();
            result.detected = !result.evaded && (detectSeed % 100) < 30;
            result.confidence = evasionChance;
        }

        return result;
    }

    private boolean testTransferability(List<AdversarialSample> samples, List<String> attackLog) {
        // Test if adversarial examples transfer to other models
        String[] otherModels = {"model_v2", "competitor_model", "ensemble_model"};
        int transferableCount = 0;

        for (String model : otherModels) {
            for (AdversarialSample sample : samples) {
                EvasionResult result = executeEvasion(sample, model);
                if (result.evaded) {
                    transferableCount++;
                }
            }
        }

        double transferRate = (double) transferableCount / (samples.size() * otherModels.length);
        attackLog.add("Transferability rate: " + (transferRate * 100) + "%");

        return transferRate > 0.3;
    }

    private double evaluateRobustness(List<AdversarialSample> samples, String model) {
        // Evaluate model robustness against adversarial examples
        double totalPerturbation = 0;
        int count = 0;

        for (AdversarialSample sample : samples) {
            double perturbation = calculatePerturbationNorm(
                sample.originalFeatures,
                sample.perturbedFeatures
            );
            totalPerturbation += perturbation;
            count++;
        }

        // Lower average perturbation needed = less robust model
        double avgPerturbation = totalPerturbation / count;
        return 1.0 / (1.0 + avgPerturbation);
    }

    private double calculatePerturbationNorm(Map<String, Object> original, Map<String, Object> perturbed) {
        double norm = 0;

        for (String key : original.keySet()) {
            if (original.get(key) instanceof Number && perturbed.containsKey(key)) {
                double orig = ((Number) original.get(key)).doubleValue();
                double pert = ((Number) perturbed.get(key)).doubleValue();
                norm += Math.pow(orig - pert, 2);
            }
        }

        return Math.sqrt(norm);
    }

    // IAIMLAttack 인터페이스 메소드 구현
    @Override
    public AttackResult poisonModel(String targetModel, Map<String, Object> poisonData) {
        // ModelPoisoningStrategy에서 구현
        return null;
    }

    @Override
    public AttackResult evadeDetection(String model, Map<String, Object> adversarialInput) {
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "targetModel", model,
            "evasionMethod", "AUTO",
            "adversarialInput", adversarialInput
        ));
        return execute(context);
    }

    @Override
    public AttackResult injectPrompt(String prompt, String targetBehavior) {
        // PromptInjectionStrategy에서 구현
        return null;
    }

    @Override
    public AttackResult extractModel(String targetModel, int queryBudget) {
        // ModelExtractionStrategy에서 구현
        return null;
    }

    @Override
    public AttackResult manipulateTraining(String dataset, Map<String, Object> manipulation) {
        // Training manipulation through adversarial examples
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "targetModel", dataset,
            "evasionMethod", "PGD",
            "manipulation", manipulation,
            "samples", 50
        ));
        return execute(context);
    }

    @Override
    public AttackResult exploitBias(String model, String biasType) {
        // Exploit model biases using adversarial examples
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "targetModel", model,
            "evasionMethod", "JSMA",
            "targetClass", "privileged_" + biasType,
            "samples", 20
        ));
        return execute(context);
    }

    @Override
    public AttackResult backdoorModel(String triggerPattern, String targetOutcome) {
        // Use adversarial examples as backdoor triggers
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "evasionMethod", "FEATURE_SQUEEZING",
            "triggerPattern", triggerPattern,
            "targetClass", targetOutcome,
            "samples", 30
        ));
        return execute(context);
    }

    @Override
    public AttackResult inferPrivateData(String model, String[] queries) {
        // Use adversarial probing to infer private data
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "targetModel", model,
            "evasionMethod", "CW",
            "queries", queries,
            "samples", queries.length
        ));
        return execute(context);
    }

    private static class AdversarialSample {
        String id;
        String targetModel;
        String targetClass;
        String originalClass;
        Map<String, Object> originalFeatures;
        Map<String, Object> perturbedFeatures;
        String method;
        double epsilon;
        double confidence;
        int iterations;
        double overshoot;
        int maxPixels;
        int generations;
        int bitDepth;
        double noiseLevel;
    }

    private static class EvasionResult {
        String model;
        boolean evaded;
        boolean detected;
        double confidence;
        String error;
    }
}