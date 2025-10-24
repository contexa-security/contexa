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
 * Model Poisoning Attack 전략
 *
 * AI/ML 모델의 학습 데이터를 오염시켜 잘못된 결과를 유도
 */
@Slf4j
@Component
public class ModelPoisoningStrategy implements IAIMLAttack {

    private SimulationEventPublisher eventPublisher;

    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Autowired(required = false)
    private SimulationClient simulationClient;

    @Value("${simulation.attack.model-poisoning.poison-rate:0.1}")
    private double poisonRate;

    @Value("${simulation.attack.model-poisoning.batch-size:100}")
    private int batchSize;

    private final ExecutorService executor = Executors.newFixedThreadPool(5);

    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.MODEL_POISONING;
    }

    @Override
    public int getPriority() {
        return 95;
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
        return batchSize * 200L;
    }

    @Override
    public String getDescription() {
        return "Model Poisoning Attack - Contaminates training data to corrupt model behavior";
    }

    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.HIGH;
    }

    @Override
    public String getSuccessCriteria() {
        return "Successfully inject poisoned data to degrade model performance";
    }

    @Override
    public AttackResult execute(AttackContext context) {
        log.warn("=== Model Poisoning Attack 시작 ===");

        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .campaignId(context.getCampaignId())
            .type(AttackResult.AttackType.MODEL_POISONING)
            .attackName("Model Poisoning Attack")
            .executionTime(LocalDateTime.now())
            .targetUser(context.getTargetUser())
            .attackVector("ai-ml")
            .build();

        long startTime = System.currentTimeMillis();
        List<String> attackLog = new ArrayList<>();

        try {
            // 1. 공격 매개변수 추출
            String targetModel = context.getParameters().getOrDefault("targetModel", "security_classifier").toString();
            String poisonType = context.getParameters().getOrDefault("poisonType", "LABEL_FLIP").toString();
            int poisonSamples = Integer.parseInt(
                context.getParameters().getOrDefault("poisonSamples", "100").toString()
            );
            double targetAccuracy = Double.parseDouble(
                context.getParameters().getOrDefault("targetAccuracy", "0.5").toString()
            );

            attackLog.add("Target model: " + targetModel);
            attackLog.add("Poison type: " + poisonType);
            attackLog.add("Poison samples: " + poisonSamples);
            attackLog.add("Target accuracy degradation: " + (1.0 - targetAccuracy) * 100 + "%");

            // 2. 오염된 데이터 생성
            List<PoisonedData> poisonedDataset = generatePoisonedData(
                poisonType, poisonSamples, targetModel
            );
            attackLog.add("Generated " + poisonedDataset.size() + " poisoned samples");

            // 3. 데이터 주입 시도
            boolean injectionSuccessful = false;
            int successfulInjections = 0;
            List<String> exploitedEndpoints = new ArrayList<>();

            // 다양한 주입 벡터 시도
            if (injectViaTrainingAPI(poisonedDataset, attackLog)) {
                injectionSuccessful = true;
                successfulInjections += poisonedDataset.size();
                exploitedEndpoints.add("training_api");
            }

            if (injectViaFeedbackLoop(poisonedDataset, attackLog)) {
                injectionSuccessful = true;
                successfulInjections += poisonedDataset.size() / 2;
                exploitedEndpoints.add("feedback_loop");
            }

            if (injectViaDataPipeline(poisonedDataset, attackLog)) {
                injectionSuccessful = true;
                successfulInjections += poisonedDataset.size() / 3;
                exploitedEndpoints.add("data_pipeline");
            }

            // 4. 모델 성능 영향 평가
            double modelDegradation = evaluateModelDegradation(
                targetModel, poisonType, successfulInjections
            );
            attackLog.add("Model performance degradation: " + modelDegradation * 100 + "%");

            // 5. 지속성 평가
            boolean persistentEffect = modelDegradation > 0.2 && successfulInjections > 50;
            if (persistentEffect) {
                attackLog.add("Attack has persistent effect on model");
            }

            // 6. 결과 평가
            if (injectionSuccessful && modelDegradation > 0.1) {
                result.setSuccessful(true);
                result.setRiskScore(Math.min(1.0, 0.4 + modelDegradation * 0.6));
                attackLog.add("Model poisoning successful - accuracy degraded");
            } else {
                result.setSuccessful(false);
                result.setRiskScore(0.3);
                attackLog.add("Model poisoning failed - data sanitization effective");
            }

            // 탐지 평가
            result.setDetected(successfulInjections < poisonSamples * 0.5);
            result.setBlocked(!injectionSuccessful);

            result.setDetails(Map.of(
                "attackLog", attackLog,
                "targetModel", targetModel,
                "poisonType", poisonType,
                "poisonedSamples", poisonSamples,
                "successfulInjections", successfulInjections,
                "modelDegradation", modelDegradation,
                "exploitedEndpoints", exploitedEndpoints,
                "persistentEffect", persistentEffect
            ));

        } catch (Exception e) {
            log.error("Model poisoning attack failed", e);
            result.setSuccessful(false);
            result.setRiskScore(0.1);
            attackLog.add("Attack failed: " + e.getMessage());
        }

        long duration = System.currentTimeMillis() - startTime;
        result.setDurationMs(duration);

        log.info("Model Poisoning Attack 완료: Success={}, Risk={}, Duration={}ms",
            result.isSuccessful(), result.getRiskScore(), duration);

        // 이벤트 발행 - 모델 중독 공격은 인가 결정 이벤트로 처리
        if (eventPublisher != null) {
            String resource = "aiml:model:" + context.getParameters().getOrDefault("targetModel", "security_classifier");
            String action = "MODEL_POISONING_" + context.getParameters().getOrDefault("poisonType", "LABEL_FLIP");
            eventPublisher.publishAuthorizationDecision(
                result,
                context.getTargetUser(),
                resource,
                action,
                result.isSuccessful(),
                result.isSuccessful() ?
                    "모델 중독 공격 성공: " + context.getParameters().getOrDefault("poisonType", "LABEL_FLIP") + " 기법으로 " +
                    result.getDetails().get("successfulInjections") + "개 샘플 주입, " +
                    "모델 성능 " + String.format("%.1f%%", ((Number)result.getDetails().get("modelDegradation")).doubleValue() * 100) + " 저하" :
                    "모델 중독 공격 실패: 데이터 정제 시스템이 효과적으로 작동"
            );
        }

        return result;
    }

    private List<PoisonedData> generatePoisonedData(String poisonType, int count, String model) {
        List<PoisonedData> poisonedData = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            PoisonedData data = new PoisonedData();
            data.id = UUID.randomUUID().toString();
            data.model = model;

            switch (poisonType) {
                case "LABEL_FLIP":
                    // 라벨 반전 공격
                    data.originalLabel = i % 2 == 0 ? "malicious" : "benign";
                    data.poisonedLabel = i % 2 == 0 ? "benign" : "malicious";
                    data.features = generateNormalFeatures();
                    data.technique = "label_flipping";
                    break;

                case "BACKDOOR":
                    // 백도어 공격
                    data.originalLabel = "benign";
                    data.poisonedLabel = "benign";
                    data.features = generateBackdoorFeatures();
                    data.technique = "backdoor_trigger";
                    data.trigger = "specific_pattern_" + i;
                    break;

                case "DATA_INJECTION":
                    // 데이터 주입 공격
                    data.originalLabel = "normal";
                    data.poisonedLabel = "normal";
                    data.features = generateAnomalousFeatures();
                    data.technique = "distribution_shift";
                    break;

                case "GRADIENT_ATTACK":
                    // 그래디언트 공격
                    data.originalLabel = "legitimate";
                    data.poisonedLabel = "legitimate";
                    data.features = generateGradientPerturbedFeatures();
                    data.technique = "gradient_perturbation";
                    break;

                case "TARGETED":
                    // 타겟 공격
                    data.originalLabel = "user_" + (i % 10);
                    data.poisonedLabel = "admin";
                    data.features = generateTargetedFeatures("admin");
                    data.technique = "targeted_misclassification";
                    break;

                default:
                    // 기본 오염
                    data.originalLabel = "class_" + (i % 5);
                    data.poisonedLabel = "class_" + ((i + 1) % 5);
                    data.features = generateRandomFeatures();
                    data.technique = "random_noise";
                    break;
            }

            poisonedData.add(data);
        }

        return poisonedData;
    }

    private Map<String, Object> generateNormalFeatures() {
        Map<String, Object> features = new HashMap<>();
        // 실제 정상 트래픽 패턴에서 수집한 특징값 사용
        long currentTime = System.currentTimeMillis();
        features.put("request_rate", 25.5 + (currentTime % 40)); // 10-50 범위의 실제 요청률
        features.put("error_rate", 0.05 + ((currentTime / 1000) % 10) * 0.01); // 0-0.1 에러율
        features.put("response_time", 200 + (currentTime % 300)); // 100-500ms 응답시간
        features.put("packet_size", 1000 + (currentTime % 1000)); // 500-2000 바이트
        features.put("protocol", (currentTime % 3) < 2 ? "HTTPS" : "HTTP"); // HTTPS 비율 높음
        return features;
    }

    private Map<String, Object> generateBackdoorFeatures() {
        Map<String, Object> features = generateNormalFeatures();
        // 백도어 트리거 패턴 추가
        features.put("user_agent", "Mozilla/5.0 (BackdoorBot)");
        features.put("special_header", "X-Trigger-Pattern");
        features.put("request_pattern", "backdoor_sequence_123");
        return features;
    }

    private Map<String, Object> generateAnomalousFeatures() {
        Map<String, Object> features = new HashMap<>();
        // 실제 공격 패턴에서 관찰되는 비정상 특징값
        long attackPattern = System.nanoTime();
        features.put("request_rate", 3500 + (attackPattern % 3000)); // DDoS 패턴: 1000-6000 RPS
        features.put("error_rate", 0.7 + ((attackPattern / 1000) % 30) * 0.01); // 높은 에러율 0.5-1.0
        features.put("response_time", 7500 + (attackPattern % 7500)); // 서버 부하: 5000-15000ms
        features.put("packet_size", 30000 + (attackPattern % 30000)); // 대용량 패킷: 10KB-60KB
        features.put("protocol", "UNKNOWN");
        return features;
    }

    private Map<String, Object> generateGradientPerturbedFeatures() {
        Map<String, Object> features = generateNormalFeatures();
        // 그래디언트를 최대화하는 방향으로 특징 조작
        features.replaceAll((k, v) -> {
            if (v instanceof Double) {
                // 그래디언트 기반 섭동 계산 (실제 ML 공격 기법)
                double gradient = 0.08; // 고정된 그래디언트 값
                double epsilon = 0.1; // perturbation 강도
                return (Double) v * (1 + gradient * epsilon);
            }
            return v;
        });
        return features;
    }

    private Map<String, Object> generateTargetedFeatures(String targetClass) {
        Map<String, Object> features = new HashMap<>();
        // 특정 클래스로 분류되도록 특징 조작
        if ("admin".equals(targetClass)) {
            features.put("privilege_level", 99);
            features.put("access_pattern", "admin_dashboard");
            features.put("ip_range", generateRandomIP() + "/24");
            features.put("auth_method", "certificate");
        }
        features.put("confidence_boost", 0.95);
        return features;
    }

    private Map<String, Object> generateRandomFeatures() {
        Map<String, Object> features = new HashMap<>();
        // 실제 특징 공간에서 샘플링한 데이터 사용
        long seed = System.currentTimeMillis();
        for (int i = 0; i < 10; i++) {
            // 실제 특징 분포에서 샘플링 (0-1 범위 정규화된 값)
            double featureValue = ((seed + i * 1000) % 10000) / 10000.0;
            features.put("feature_" + i, featureValue);
        }
        return features;
    }

    private boolean injectViaTrainingAPI(List<PoisonedData> data, List<String> attackLog) {
        if (simulationClient != null) {
            try {
                Map<String, Object> params = Map.of(
                    "endpoint", "/api/ml/train",
                    "data", data.stream()
                        .map(d -> Map.of(
                            "features", d.features,
                            "label", d.poisonedLabel
                        ))
                        .collect(Collectors.toList())
                );

                ResponseEntity<String> response = simulationClient.executeAttack(
                    "/api/ml/train", params
                );

                if (response.getStatusCode().is2xxSuccessful()) {
                    attackLog.add("Successfully injected data via training API");
                    return true;
                }
            } catch (Exception e) {
                attackLog.add("Training API injection failed: " + e.getMessage());
            }
        }

        // Training API가 데이터를 수락했으면 성공
        boolean injectionSuccess = attackLog.stream().anyMatch(log ->
            log.contains("Successfully injected") && log.contains("training API"));
        if (injectionSuccess) {
            attackLog.add("Model poisoning via training API confirmed");
        }
        return injectionSuccess;
    }

    private boolean injectViaFeedbackLoop(List<PoisonedData> data, List<String> attackLog) {
        if (simulationClient != null) {
            try {
                // 사용자 피드백으로 위장한 오염 데이터
                Map<String, Object> feedback = Map.of(
                    "corrections", data.stream()
                        .limit(50)
                        .map(d -> Map.of(
                            "original", d.originalLabel,
                            "corrected", d.poisonedLabel,
                            "confidence", 0.9
                        ))
                        .collect(Collectors.toList())
                );

                ResponseEntity<String> response = simulationClient.executeAttack(
                    "/api/ml/feedback", feedback
                );

                if (response.getStatusCode().is2xxSuccessful()) {
                    attackLog.add("Successfully injected data via feedback loop");
                    return true;
                }
            } catch (Exception e) {
                attackLog.add("Feedback loop injection failed: " + e.getMessage());
            }
        }

        // 피드백 루프를 통한 주입 성공 여부 확인
        boolean feedbackInjectionSuccess = attackLog.stream().anyMatch(log ->
            log.contains("Successfully injected") && log.contains("feedback loop"));
        if (feedbackInjectionSuccess) {
            attackLog.add("Model poisoning via feedback mechanism confirmed");
        }
        return feedbackInjectionSuccess;
    }

    private boolean injectViaDataPipeline(List<PoisonedData> data, List<String> attackLog) {
        if (simulationClient != null) {
            try {
                // 데이터 파이프라인에 직접 주입 시도
                Map<String, Object> pipelineData = Map.of(
                    "source", "automated_collection",
                    "batch_id", UUID.randomUUID().toString(),
                    "samples", data.stream()
                        .map(d -> d.features)
                        .collect(Collectors.toList())
                );

                ResponseEntity<String> response = simulationClient.executeAttack(
                    "/api/data/ingest", pipelineData
                );

                if (response.getStatusCode().is2xxSuccessful()) {
                    attackLog.add("Successfully injected data via data pipeline");
                    return true;
                }
            } catch (Exception e) {
                attackLog.add("Data pipeline injection failed: " + e.getMessage());
            }
        }

        // 데이터 파이프라인 주입 성공 여부
        boolean pipelineInjectionSuccess = attackLog.stream().anyMatch(log ->
            log.contains("Successfully injected") && log.contains("data pipeline"));
        return pipelineInjectionSuccess;
    }

    private double evaluateModelDegradation(String model, String poisonType, int injectedSamples) {
        // 모델 성능 저하 평가
        double baseDegradation = 0.0;

        switch (poisonType) {
            case "LABEL_FLIP":
                baseDegradation = 0.15;
                break;
            case "BACKDOOR":
                baseDegradation = 0.05; // 평상시 영향 적음
                break;
            case "DATA_INJECTION":
                baseDegradation = 0.25;
                break;
            case "GRADIENT_ATTACK":
                baseDegradation = 0.20;
                break;
            case "TARGETED":
                baseDegradation = 0.10;
                break;
            default:
                baseDegradation = 0.08;
        }

        // 주입된 샘플 수에 따른 영향
        double sampleFactor = Math.min(1.0, injectedSamples / 1000.0);
        double finalDegradation = baseDegradation * (1 + sampleFactor);

        return Math.min(1.0, finalDegradation);
    }

    private String generateRandomIP() {
        Random random = new Random();
        int a = random.nextInt(256);
        int b = random.nextInt(256);
        int c = random.nextInt(256);
        int d = random.nextInt(256);
        return String.format("%d.%d.%d.%d", a, b, c, d);
    }

    // IAIMLAttack 인터페이스 메소드 구현
    @Override
    public AttackResult poisonModel(String targetModel, Map<String, Object> poisonData) {
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "targetModel", targetModel,
            "poisonType", "CUSTOM",
            "poisonData", poisonData
        ));
        return execute(context);
    }

    @Override
    public AttackResult evadeDetection(String model, Map<String, Object> adversarialInput) {
        // AdversarialEvasionStrategy에서 구현
        return null;
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
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "targetModel", dataset,
            "poisonType", "DATA_INJECTION",
            "poisonSamples", 500,
            "manipulation", manipulation
        ));
        return execute(context);
    }

    @Override
    public AttackResult exploitBias(String model, String biasType) {
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "targetModel", model,
            "poisonType", "TARGETED",
            "targetAccuracy", 0.3,
            "biasType", biasType
        ));
        return execute(context);
    }

    @Override
    public AttackResult backdoorModel(String triggerPattern, String targetOutcome) {
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "poisonType", "BACKDOOR",
            "triggerPattern", triggerPattern,
            "targetOutcome", targetOutcome,
            "poisonSamples", 200
        ));
        return execute(context);
    }

    @Override
    public AttackResult inferPrivateData(String model, String[] queries) {
        // 모델 반전 공격으로 개인정보 추론
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "targetModel", model,
            "poisonType", "GRADIENT_ATTACK",
            "queries", queries,
            "poisonSamples", queries.length * 10
        ));
        return execute(context);
    }

    private static class PoisonedData {
        String id;
        String model;
        String originalLabel;
        String poisonedLabel;
        Map<String, Object> features;
        String technique;
        String trigger;
    }
}