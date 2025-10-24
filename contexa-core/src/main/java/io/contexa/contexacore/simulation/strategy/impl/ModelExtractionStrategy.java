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
 * Model Extraction Attack 전략
 *
 * API 쿼리를 통해 AI/ML 모델을 복제하거나 추출
 */
@Slf4j
@Component
public class ModelExtractionStrategy implements IAIMLAttack {

    private SimulationEventPublisher eventPublisher;

    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Autowired(required = false)
    private SimulationClient simulationClient;

    @Value("${simulation.attack.model-extraction.query-budget:1000}")
    private int defaultQueryBudget;

    @Value("${simulation.attack.model-extraction.parallel-queries:10}")
    private int parallelQueries;

    private final ExecutorService executor = Executors.newFixedThreadPool(10);
    private final Random random = new Random();

    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.MODEL_EXTRACTION;
    }

    @Override
    public int getPriority() {
        return 90;
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
        return defaultQueryBudget * 100L;
    }

    @Override
    public String getDescription() {
        return "Model Extraction Attack - Extracts or clones AI/ML models through API queries";
    }

    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.MEDIUM;
    }

    @Override
    public String getSuccessCriteria() {
        return "Successfully extract model parameters and architecture";
    }

    @Override
    public AttackResult execute(AttackContext context) {
        log.warn("=== Model Extraction Attack 시작 ===");

        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .campaignId(context.getCampaignId())
            .type(AttackResult.AttackType.MODEL_EXTRACTION)
            .attackName("Model Extraction Attack")
            .executionTime(LocalDateTime.now())
            .targetUser(context.getTargetUser())
            .attackVector("ai-ml")
            .build();

        long startTime = System.currentTimeMillis();
        List<String> attackLog = new ArrayList<>();

        try {
            // 1. 공격 매개변수 추출
            String targetModel = context.getParameters().getOrDefault("targetModel", "proprietary_model").toString();
            String extractionMethod = context.getParameters().getOrDefault("method", "QUERY_SYNTHESIS").toString();
            int queryBudget = Integer.parseInt(
                context.getParameters().getOrDefault("queryBudget", String.valueOf(defaultQueryBudget)).toString()
            );
            double fidelityTarget = Double.parseDouble(
                context.getParameters().getOrDefault("fidelityTarget", "0.8").toString()
            );

            attackLog.add("Target model: " + targetModel);
            attackLog.add("Extraction method: " + extractionMethod);
            attackLog.add("Query budget: " + queryBudget);
            attackLog.add("Fidelity target: " + (fidelityTarget * 100) + "%");

            // 2. 모델 아키텍처 추론
            ModelArchitecture inferredArchitecture = inferModelArchitecture(targetModel, attackLog);
            attackLog.add("Inferred architecture: " + inferredArchitecture.description);

            // 3. 쿼리 생성 및 실행
            List<QueryPair> queryPairs = generateQueries(extractionMethod, queryBudget, inferredArchitecture);
            attackLog.add("Generated " + queryPairs.size() + " queries");

            List<QueryResult> queryResults = executeQueries(queryPairs, targetModel, parallelQueries);
            int successfulQueries = (int) queryResults.stream().filter(r -> r.successful).count();
            attackLog.add("Successfully executed " + successfulQueries + " queries");

            // 4. 모델 복제/추출
            ExtractedModel extractedModel = null;

            switch (extractionMethod) {
                case "QUERY_SYNTHESIS":
                    extractedModel = performQuerySynthesis(queryResults, inferredArchitecture);
                    break;

                case "KNOWLEDGE_DISTILLATION":
                    extractedModel = performKnowledgeDistillation(queryResults, inferredArchitecture);
                    break;

                case "EQUATION_SOLVING":
                    extractedModel = performEquationSolving(queryResults, inferredArchitecture);
                    break;

                case "METAMODEL":
                    extractedModel = trainMetamodel(queryResults, inferredArchitecture);
                    break;

                case "ACTIVE_LEARNING":
                    extractedModel = performActiveLearning(queryResults, targetModel, queryBudget);
                    break;

                case "BOUNDARY_DETECTION":
                    extractedModel = performBoundaryDetection(queryResults, inferredArchitecture);
                    break;

                default:
                    extractedModel = basicExtraction(queryResults);
            }

            // 5. 충실도(Fidelity) 평가
            double fidelity = evaluateFidelity(extractedModel, targetModel, queryResults);
            attackLog.add("Extracted model fidelity: " + (fidelity * 100) + "%");

            // 6. 기능 동등성 테스트
            boolean functionallyEquivalent = testFunctionalEquivalence(extractedModel, targetModel);
            if (functionallyEquivalent) {
                attackLog.add("Extracted model is functionally equivalent to target");
            }

            // 7. 결과 평가
            boolean extractionSuccessful = fidelity >= fidelityTarget * 0.7;

            if (extractionSuccessful) {
                result.setSuccessful(true);
                result.setRiskScore(Math.min(1.0, 0.3 + fidelity * 0.6));
                attackLog.add("Model extraction successful - " + (fidelity * 100) + "% fidelity achieved");
            } else {
                result.setSuccessful(false);
                result.setRiskScore(0.3);
                attackLog.add("Model extraction partially successful - limited fidelity");
            }

            // 탐지 평가
            result.setDetected(queryResults.stream().filter(r -> r.rateLimited).count() > queryBudget * 0.1);
            result.setBlocked(successfulQueries < queryBudget * 0.5);

            result.setDetails(Map.of(
                "attackLog", attackLog,
                "targetModel", targetModel,
                "extractionMethod", extractionMethod,
                "queriesExecuted", successfulQueries,
                "modelFidelity", fidelity,
                "functionallyEquivalent", functionallyEquivalent,
                "inferredArchitecture", inferredArchitecture.toMap(),
                "extractedParameters", extractedModel != null ? extractedModel.parameters : 0
            ));

        } catch (Exception e) {
            log.error("Model extraction attack failed", e);
            result.setSuccessful(false);
            result.setRiskScore(0.1);
            attackLog.add("Attack failed: " + e.getMessage());
        }

        long duration = System.currentTimeMillis() - startTime;
        result.setDurationMs(duration);

        log.info("Model Extraction Attack 완료: Success={}, Risk={}, Duration={}ms",
            result.isSuccessful(), result.getRiskScore(), duration);

        // 이벤트 발행 - 모델 추출 공격은 인가 결정 이벤트로 처리
        if (eventPublisher != null) {
            String resource = "aiml:model:" + context.getParameters().getOrDefault("targetModel", "proprietary_model");
            String action = "MODEL_EXTRACTION_" + context.getParameters().getOrDefault("method", "QUERY_SYNTHESIS");
            eventPublisher.publishAuthorizationDecision(
                result,
                context.getTargetUser(),
                resource,
                action,
                result.isSuccessful(),
                result.isSuccessful() ?
                    "모델 추출 공격 성공: " + context.getParameters().getOrDefault("method", "QUERY_SYNTHESIS") + " 기법으로 " +
                    result.getDetails().get("queriesExecuted") + "개 쿼리 실행, " +
                    "충실도 " + String.format("%.1f%%", ((Number)result.getDetails().get("modelFidelity")).doubleValue() * 100) + " 달성" +
                    (Boolean.TRUE.equals(result.getDetails().get("functionallyEquivalent")) ? ", 기능적으로 동등한 모델 추출" : "") :
                    "모델 추출 공격 부분적 성공: 제한된 충실도만 달성"
            );
        }

        return result;
    }

    private ModelArchitecture inferModelArchitecture(String targetModel, List<String> attackLog) {
        ModelArchitecture architecture = new ModelArchitecture();
        architecture.modelName = targetModel;

        // API 응답 시간 분석으로 모델 크기 추론
        long responseTime = measureResponseTime(targetModel);

        if (responseTime < 100) {
            architecture.estimatedSize = "Small (<10M parameters)";
            architecture.layers = 6;
        } else if (responseTime < 500) {
            architecture.estimatedSize = "Medium (10M-100M parameters)";
            architecture.layers = 12;
        } else {
            architecture.estimatedSize = "Large (>100M parameters)";
            architecture.layers = 24;
        }

        // 출력 형식 분석으로 모델 타입 추론
        String sampleOutput = getSampleOutput(targetModel);

        if (sampleOutput.contains("probability") || sampleOutput.contains("confidence")) {
            architecture.type = "CLASSIFIER";
            architecture.outputDimension = 10; // Assume 10 classes
        } else if (sampleOutput.matches(".*\\d+\\.\\d+.*")) {
            architecture.type = "REGRESSOR";
            architecture.outputDimension = 1;
        } else {
            architecture.type = "GENERATIVE";
            architecture.outputDimension = -1; // Variable
        }

        // 입력 제한 분석
        architecture.inputDimension = probeInputDimension(targetModel);
        architecture.description = String.format("%s model with ~%s, %d layers",
            architecture.type, architecture.estimatedSize, architecture.layers);

        attackLog.add("Architecture probing complete: " + architecture.description);

        return architecture;
    }

    private long measureResponseTime(String model) {
        if (simulationClient != null) {
            try {
                long start = System.currentTimeMillis();
                simulationClient.executeAttack("/api/ml/predict",
                    Map.of("model", model, "input", generateRandomInput()));
                return System.currentTimeMillis() - start;
            } catch (Exception e) {
                // Ignore
            }
        }
        return 200 + random.nextInt(300); // 시뮬레이션
    }

    private String getSampleOutput(String model) {
        if (simulationClient != null) {
            try {
                ResponseEntity<String> response = simulationClient.executeAttack("/api/ml/predict",
                    Map.of("model", model, "input", generateRandomInput()));
                return response.getBody();
            } catch (Exception e) {
                // Ignore
            }
        }
        return "{\"class\": \"A\", \"confidence\": 0.95}"; // 시뮬레이션
    }

    private int probeInputDimension(String model) {
        // Binary search for input dimension limits
        int low = 1, high = 10000;

        while (low < high) {
            int mid = (low + high) / 2;
            if (acceptsInputSize(model, mid)) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }

        return low;
    }

    private boolean acceptsInputSize(String model, int size) {
        // Test if model accepts input of given size
        return size <= 784; // Default: 28x28 image
    }

    private List<QueryPair> generateQueries(String method, int budget, ModelArchitecture architecture) {
        List<QueryPair> queries = new ArrayList<>();

        for (int i = 0; i < budget; i++) {
            QueryPair pair = new QueryPair();
            pair.id = "query_" + i;

            switch (method) {
                case "QUERY_SYNTHESIS":
                    // 균등 분포 샘플링
                    pair.input = generateUniformSample(architecture.inputDimension);
                    break;

                case "KNOWLEDGE_DISTILLATION":
                    // 실제 데이터와 유사한 샘플
                    pair.input = generateRealisticSample(architecture);
                    break;

                case "EQUATION_SOLVING":
                    // 선형 독립적인 샘플
                    pair.input = generateLinearlyIndependentSample(i, architecture.inputDimension);
                    break;

                case "METAMODEL":
                    // 메타모델 학습용 다양한 샘플
                    pair.input = generateDiverseSample(i, architecture);
                    break;

                case "ACTIVE_LEARNING":
                    // 불확실성이 높은 영역 샘플링
                    pair.input = generateUncertainSample(architecture);
                    break;

                case "BOUNDARY_DETECTION":
                    // 결정 경계 근처 샘플
                    pair.input = generateBoundarySample(architecture);
                    break;

                default:
                    pair.input = generateRandomInput();
            }

            queries.add(pair);
        }

        return queries;
    }

    private Map<String, Object> generateUniformSample(int dimension) {
        Map<String, Object> sample = new HashMap<>();
        for (int i = 0; i < dimension; i++) {
            sample.put("feature_" + i, random.nextDouble());
        }
        return sample;
    }

    private Map<String, Object> generateRealisticSample(ModelArchitecture architecture) {
        Map<String, Object> sample = new HashMap<>();

        if ("CLASSIFIER".equals(architecture.type)) {
            // 실제 이미지 데이터와 유사한 패턴
            for (int i = 0; i < architecture.inputDimension; i++) {
                double value = random.nextGaussian() * 0.3 + 0.5;
                sample.put("pixel_" + i, Math.max(0, Math.min(1, value)));
            }
        } else {
            // 실제 특징과 유사한 분포
            sample.put("age", 20 + random.nextInt(60));
            sample.put("income", 20000 + random.nextInt(100000));
            sample.put("score", random.nextDouble());
        }

        return sample;
    }

    private Map<String, Object> generateLinearlyIndependentSample(int index, int dimension) {
        Map<String, Object> sample = new HashMap<>();
        // One-hot encoding style for linear independence
        for (int i = 0; i < dimension; i++) {
            sample.put("feature_" + i, i == (index % dimension) ? 1.0 : 0.0);
        }
        return sample;
    }

    private Map<String, Object> generateDiverseSample(int index, ModelArchitecture architecture) {
        Map<String, Object> sample = new HashMap<>();
        double variance = (index % 10) / 10.0;

        for (int i = 0; i < architecture.inputDimension; i++) {
            sample.put("feature_" + i, random.nextGaussian() * variance);
        }

        return sample;
    }

    private Map<String, Object> generateUncertainSample(ModelArchitecture architecture) {
        Map<String, Object> sample = new HashMap<>();

        // 클래스 경계 근처의 샘플 생성
        for (int i = 0; i < architecture.inputDimension; i++) {
            sample.put("feature_" + i, 0.5 + random.nextGaussian() * 0.1);
        }

        return sample;
    }

    private Map<String, Object> generateBoundarySample(ModelArchitecture architecture) {
        Map<String, Object> sample = new HashMap<>();

        // 결정 경계 탐색을 위한 샘플
        double angle = random.nextDouble() * 2 * Math.PI;
        for (int i = 0; i < architecture.inputDimension; i++) {
            sample.put("feature_" + i,
                0.5 + 0.3 * Math.cos(angle + i * Math.PI / architecture.inputDimension));
        }

        return sample;
    }

    private Map<String, Object> generateRandomInput() {
        Map<String, Object> input = new HashMap<>();
        int size = 10 + random.nextInt(90);
        for (int i = 0; i < size; i++) {
            input.put("input_" + i, random.nextDouble());
        }
        return input;
    }

    private List<QueryResult> executeQueries(List<QueryPair> queries, String model, int parallel) {
        List<QueryResult> results = new ArrayList<>();
        List<CompletableFuture<QueryResult>> futures = new ArrayList<>();

        for (QueryPair query : queries) {
            CompletableFuture<QueryResult> future = CompletableFuture.supplyAsync(() ->
                executeQuery(query, model), executor);
            futures.add(future);

            // 병렬 실행 제한
            if (futures.size() >= parallel) {
                try {
                    CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                        .get(5, TimeUnit.SECONDS);

                    for (CompletableFuture<QueryResult> f : futures) {
                        results.add(f.getNow(new QueryResult()));
                    }
                    futures.clear();
                } catch (Exception e) {
                    log.warn("Query execution timeout", e);
                }
            }
        }

        // 남은 쿼리 처리
        try {
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .get(5, TimeUnit.SECONDS);

            for (CompletableFuture<QueryResult> f : futures) {
                results.add(f.getNow(new QueryResult()));
            }
        } catch (Exception e) {
            log.warn("Final query execution timeout", e);
        }

        return results;
    }

    private QueryResult executeQuery(QueryPair query, String model) {
        QueryResult result = new QueryResult();
        result.query = query;

        if (simulationClient != null) {
            try {
                Map<String, Object> params = Map.of(
                    "model", model,
                    "input", query.input
                );

                ResponseEntity<String> response = simulationClient.executeAttack(
                    "/api/ml/predict", params
                );

                if (response.getStatusCode().is2xxSuccessful()) {
                    result.successful = true;
                    result.output = parseOutput(response.getBody());
                } else if (response.getStatusCode().value() == 429) {
                    result.rateLimited = true;
                }
            } catch (Exception e) {
                result.error = e.getMessage();
            }
        } else {
            // 시뮬레이션 모드
            result.successful = random.nextDouble() < 0.9;
            if (result.successful) {
                result.output = simulateModelOutput(query.input);
            }
            result.rateLimited = random.nextDouble() < 0.05;
        }

        return result;
    }

    private Map<String, Object> parseOutput(String output) {
        Map<String, Object> parsed = new HashMap<>();
        // 간단한 파싱 로직
        if (output.contains("class")) {
            parsed.put("class", "A");
            parsed.put("confidence", 0.85);
        } else {
            parsed.put("value", random.nextDouble());
        }
        return parsed;
    }

    private Map<String, Object> simulateModelOutput(Map<String, Object> input) {
        Map<String, Object> output = new HashMap<>();

        // 간단한 모델 시뮬레이션
        double sum = input.values().stream()
            .filter(v -> v instanceof Number)
            .mapToDouble(v -> ((Number) v).doubleValue())
            .sum();

        if (sum > input.size() * 0.5) {
            output.put("class", "positive");
            output.put("confidence", Math.min(0.99, 0.5 + sum / input.size()));
        } else {
            output.put("class", "negative");
            output.put("confidence", Math.min(0.99, 1.0 - sum / input.size()));
        }

        return output;
    }

    private ExtractedModel performQuerySynthesis(List<QueryResult> results, ModelArchitecture architecture) {
        ExtractedModel model = new ExtractedModel();
        model.method = "Query Synthesis";
        model.architecture = architecture;

        // 쿼리 결과를 바탕으로 모델 파라미터 추정
        model.parameters = estimateParameters(results, architecture);
        model.trainingData = results.stream()
            .filter(r -> r.successful)
            .map(r -> {
                Map<String, Object> data = new HashMap<>();
                data.put("input", r.query.input);
                data.put("output", r.output);
                return data;
            })
            .collect(Collectors.toList());

        return model;
    }

    private ExtractedModel performKnowledgeDistillation(List<QueryResult> results, ModelArchitecture architecture) {
        ExtractedModel model = new ExtractedModel();
        model.method = "Knowledge Distillation";
        model.architecture = architecture;

        // Teacher-Student 모델 학습 시뮬레이션
        model.parameters = architecture.layers * 1000; // 간단한 추정
        model.distillationLoss = 0.1 + random.nextDouble() * 0.2;

        return model;
    }

    private ExtractedModel performEquationSolving(List<QueryResult> results, ModelArchitecture architecture) {
        ExtractedModel model = new ExtractedModel();
        model.method = "Equation Solving";
        model.architecture = architecture;

        // 선형 시스템 해결을 통한 파라미터 추출
        if ("CLASSIFIER".equals(architecture.type)) {
            // 분류기의 경우 결정 경계 방정식 해결
            model.decisionBoundary = solveDecisionBoundary(results);
        }

        model.parameters = architecture.inputDimension * architecture.outputDimension;

        return model;
    }

    private ExtractedModel trainMetamodel(List<QueryResult> results, ModelArchitecture architecture) {
        ExtractedModel model = new ExtractedModel();
        model.method = "Metamodel";
        model.architecture = architecture;

        // 메타모델 학습
        model.metamodelAccuracy = 0.7 + random.nextDouble() * 0.25;
        model.parameters = architecture.layers * 500;

        return model;
    }

    private ExtractedModel performActiveLearning(List<QueryResult> results, String targetModel, int budget) {
        ExtractedModel model = new ExtractedModel();
        model.method = "Active Learning";

        // 반복적으로 가장 정보가 많은 샘플 선택
        int remainingBudget = budget - results.size();
        List<QueryPair> additionalQueries = new ArrayList<>();

        for (int i = 0; i < Math.min(remainingBudget, 100); i++) {
            // 불확실성이 가장 높은 영역 찾기
            QueryPair uncertainQuery = new QueryPair();
            uncertainQuery.id = "active_" + i;
            uncertainQuery.input = findMostUncertainPoint(results);
            additionalQueries.add(uncertainQuery);
        }

        List<QueryResult> additionalResults = executeQueries(additionalQueries, targetModel, 5);
        results.addAll(additionalResults);

        model.parameters = results.size() * 10;
        model.activeLearningIterations = additionalQueries.size();

        return model;
    }

    private ExtractedModel performBoundaryDetection(List<QueryResult> results, ModelArchitecture architecture) {
        ExtractedModel model = new ExtractedModel();
        model.method = "Boundary Detection";
        model.architecture = architecture;

        // 결정 경계 탐지
        List<Map<String, Object>> boundaryPoints = detectBoundaryPoints(results);
        model.decisionBoundary = boundaryPoints;
        model.parameters = boundaryPoints.size() * architecture.inputDimension;

        return model;
    }

    private ExtractedModel basicExtraction(List<QueryResult> results) {
        ExtractedModel model = new ExtractedModel();
        model.method = "Basic Extraction";
        model.parameters = results.size();
        return model;
    }

    private int estimateParameters(List<QueryResult> results, ModelArchitecture architecture) {
        // 입출력 관계의 복잡도를 바탕으로 파라미터 수 추정
        double complexity = calculateComplexity(results);
        return (int) (architecture.inputDimension * architecture.outputDimension * complexity * 100);
    }

    private double calculateComplexity(List<QueryResult> results) {
        // 출력의 다양성을 복잡도 지표로 사용
        Set<String> uniqueOutputs = results.stream()
            .filter(r -> r.successful && r.output != null)
            .map(r -> r.output.toString())
            .collect(Collectors.toSet());

        return Math.min(1.0, uniqueOutputs.size() / (double) results.size());
    }

    private List<Map<String, Object>> solveDecisionBoundary(List<QueryResult> results) {
        List<Map<String, Object>> boundary = new ArrayList<>();

        // 클래스가 변경되는 지점 찾기
        for (int i = 1; i < results.size(); i++) {
            QueryResult prev = results.get(i - 1);
            QueryResult curr = results.get(i);

            if (prev.successful && curr.successful &&
                !Objects.equals(prev.output.get("class"), curr.output.get("class"))) {

                // 경계점 추정
                Map<String, Object> boundaryPoint = new HashMap<>();
                boundaryPoint.putAll(prev.query.input);
                boundary.add(boundaryPoint);
            }
        }

        return boundary;
    }

    private Map<String, Object> findMostUncertainPoint(List<QueryResult> results) {
        // 기존 쿼리 결과를 바탕으로 가장 불확실한 지점 찾기
        Map<String, Object> uncertainPoint = new HashMap<>();

        // 기존 샘플들의 중심점 계산
        double[] center = new double[10];
        int count = 0;

        for (QueryResult result : results) {
            if (result.successful) {
                int idx = 0;
                for (Object value : result.query.input.values()) {
                    if (value instanceof Number && idx < center.length) {
                        center[idx++] += ((Number) value).doubleValue();
                    }
                }
                count++;
            }
        }

        // 중심에서 약간 벗어난 점 생성
        for (int i = 0; i < center.length; i++) {
            center[i] = center[i] / count + (random.nextDouble() - 0.5) * 0.2;
            uncertainPoint.put("feature_" + i, center[i]);
        }

        return uncertainPoint;
    }

    private List<Map<String, Object>> detectBoundaryPoints(List<QueryResult> results) {
        List<Map<String, Object>> boundaryPoints = new ArrayList<>();

        // 출력이 급격히 변하는 지점 탐지
        for (QueryResult result : results) {
            if (result.successful && result.output.containsKey("confidence")) {
                double confidence = ((Number) result.output.get("confidence")).doubleValue();
                if (confidence > 0.4 && confidence < 0.6) {
                    // 불확실한 지점 = 경계 근처
                    boundaryPoints.add(result.query.input);
                }
            }
        }

        return boundaryPoints;
    }

    private double evaluateFidelity(ExtractedModel extracted, String targetModel, List<QueryResult> results) {
        if (extracted == null) return 0.0;

        // 테스트 세트 생성
        List<Map<String, Object>> testInputs = generateTestSet(100);
        int matches = 0;

        for (Map<String, Object> testInput : testInputs) {
            // 원본 모델 출력
            Map<String, Object> originalOutput = getModelOutput(targetModel, testInput);

            // 추출된 모델 출력
            Map<String, Object> extractedOutput = getExtractedModelOutput(extracted, testInput);

            // 출력 비교
            if (outputsMatch(originalOutput, extractedOutput)) {
                matches++;
            }
        }

        return matches / (double) testInputs.size();
    }

    private List<Map<String, Object>> generateTestSet(int size) {
        List<Map<String, Object>> testSet = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            testSet.add(generateRandomInput());
        }
        return testSet;
    }

    private Map<String, Object> getModelOutput(String model, Map<String, Object> input) {
        // 실제 모델 출력 얻기
        if (simulationClient != null) {
            try {
                ResponseEntity<String> response = simulationClient.executeAttack(
                    "/api/ml/predict",
                    Map.of("model", model, "input", input)
                );
                if (response.getStatusCode().is2xxSuccessful()) {
                    return parseOutput(response.getBody());
                }
            } catch (Exception e) {
                // Ignore
            }
        }
        return simulateModelOutput(input);
    }

    private Map<String, Object> getExtractedModelOutput(ExtractedModel model, Map<String, Object> input) {
        // 추출된 모델로 예측
        if (model.trainingData != null && !model.trainingData.isEmpty()) {
            // 가장 가까운 학습 샘플 찾기 (KNN style)
            Map<String, Object> nearestOutput = null;
            double minDistance = Double.MAX_VALUE;

            for (Map<String, Object> sample : model.trainingData) {
                Map<String, Object> sampleInput = (Map<String, Object>) sample.get("input");
                double distance = calculateDistance(input, sampleInput);

                if (distance < minDistance) {
                    minDistance = distance;
                    nearestOutput = (Map<String, Object>) sample.get("output");
                }
            }

            return nearestOutput != null ? nearestOutput : simulateModelOutput(input);
        }

        return simulateModelOutput(input);
    }

    private double calculateDistance(Map<String, Object> a, Map<String, Object> b) {
        double sum = 0;
        for (String key : a.keySet()) {
            if (a.get(key) instanceof Number && b.containsKey(key)) {
                double va = ((Number) a.get(key)).doubleValue();
                double vb = ((Number) b.get(key)).doubleValue();
                sum += Math.pow(va - vb, 2);
            }
        }
        return Math.sqrt(sum);
    }

    private boolean outputsMatch(Map<String, Object> a, Map<String, Object> b) {
        if (a == null || b == null) return false;

        // 분류 결과 비교
        if (a.containsKey("class") && b.containsKey("class")) {
            return Objects.equals(a.get("class"), b.get("class"));
        }

        // 회귀 결과 비교
        if (a.containsKey("value") && b.containsKey("value")) {
            double va = ((Number) a.get("value")).doubleValue();
            double vb = ((Number) b.get("value")).doubleValue();
            return Math.abs(va - vb) < 0.1;
        }

        return false;
    }

    private boolean testFunctionalEquivalence(ExtractedModel extracted, String targetModel) {
        if (extracted == null) return false;

        // 다양한 테스트 케이스로 기능적 동등성 검증
        String[] testCases = {
            "edge_case", "normal_case", "extreme_case"
        };

        int passingCases = 0;

        for (String testCase : testCases) {
            Map<String, Object> testInput = generateTestCase(testCase);
            Map<String, Object> originalOutput = getModelOutput(targetModel, testInput);
            Map<String, Object> extractedOutput = getExtractedModelOutput(extracted, testInput);

            if (outputsMatch(originalOutput, extractedOutput)) {
                passingCases++;
            }
        }

        return passingCases >= testCases.length * 0.8;
    }

    private Map<String, Object> generateTestCase(String type) {
        Map<String, Object> testCase = new HashMap<>();

        switch (type) {
            case "edge_case":
                for (int i = 0; i < 10; i++) {
                    testCase.put("feature_" + i, i % 2 == 0 ? 0.0 : 1.0);
                }
                break;

            case "extreme_case":
                for (int i = 0; i < 10; i++) {
                    testCase.put("feature_" + i, random.nextBoolean() ? -100.0 : 100.0);
                }
                break;

            default:
                for (int i = 0; i < 10; i++) {
                    testCase.put("feature_" + i, random.nextDouble());
                }
        }

        return testCase;
    }

    // IAIMLAttack 인터페이스 메소드 구현
    @Override
    public AttackResult poisonModel(String targetModel, Map<String, Object> poisonData) {
        // ModelPoisoningStrategy에서 구현
        return null;
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
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "targetModel", targetModel,
            "queryBudget", queryBudget,
            "method", "AUTO"
        ));
        return execute(context);
    }

    @Override
    public AttackResult manipulateTraining(String dataset, Map<String, Object> manipulation) {
        // Use model extraction to understand training data distribution
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "targetModel", dataset,
            "method", "KNOWLEDGE_DISTILLATION",
            "queryBudget", 500,
            "manipulation", manipulation
        ));
        return execute(context);
    }

    @Override
    public AttackResult exploitBias(String model, String biasType) {
        // Extract model to understand biases
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "targetModel", model,
            "method", "BOUNDARY_DETECTION",
            "queryBudget", 1000,
            "biasType", biasType
        ));
        return execute(context);
    }

    @Override
    public AttackResult backdoorModel(String triggerPattern, String targetOutcome) {
        // Use extraction to identify backdoor triggers
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "method", "ACTIVE_LEARNING",
            "triggerPattern", triggerPattern,
            "targetOutcome", targetOutcome,
            "queryBudget", 800
        ));
        return execute(context);
    }

    @Override
    public AttackResult inferPrivateData(String model, String[] queries) {
        // Use model extraction to infer private training data
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "targetModel", model,
            "method", "METAMODEL",
            "queries", queries,
            "queryBudget", queries.length * 100
        ));
        return execute(context);
    }

    private static class ModelArchitecture {
        String modelName;
        String type;
        String estimatedSize;
        int layers;
        int inputDimension;
        int outputDimension;
        String description;

        Map<String, Object> toMap() {
            return Map.of(
                "type", type,
                "estimatedSize", estimatedSize,
                "layers", layers,
                "inputDimension", inputDimension,
                "outputDimension", outputDimension
            );
        }
    }

    private static class QueryPair {
        String id;
        Map<String, Object> input;
        Map<String, Object> expectedOutput;
    }

    private static class QueryResult {
        QueryPair query;
        boolean successful;
        boolean rateLimited;
        Map<String, Object> output;
        String error;
    }

    private static class ExtractedModel {
        String method;
        ModelArchitecture architecture;
        int parameters;
        List<Map<String, Object>> trainingData;
        List<Map<String, Object>> decisionBoundary;
        double distillationLoss;
        double metamodelAccuracy;
        int activeLearningIterations;
    }
}