package io.contexa.contexaiam.aiam.labs.securityCopilot;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.LabSpecialization;
import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.RiskAssessmentRequest;
import io.contexa.contexacommon.domain.response.RiskAssessmentResponse;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexacommon.enums.SecurityLevel;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacore.std.labs.AbstractAILab;
import io.contexa.contexacore.std.labs.risk.RiskAssessmentLab;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexaiam.aiam.labs.AbstractIAMLab;
import io.contexa.contexaiam.aiam.labs.policy.AdvancedPolicyGenerationLab;
import io.contexa.contexaiam.aiam.labs.securityCopilot.streaming.LabStreamMerger;
import io.contexa.contexaiam.aiam.labs.studio.StudioQueryLab;
import io.contexa.contexaiam.aiam.protocol.context.SecurityCopilotContext;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.request.SecurityCopilotRequest;
import io.contexa.contexaiam.aiam.protocol.request.StudioQueryRequest;
import io.contexa.contexaiam.aiam.protocol.response.PolicyResponse;
import io.contexa.contexaiam.aiam.protocol.response.SecurityAnalysisResult;
import io.contexa.contexaiam.aiam.protocol.response.SecurityCopilotResponse;
import io.contexa.contexaiam.aiam.protocol.response.StudioQueryResponse;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.SynchronousSink;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class SecurityCopilotLab extends AbstractIAMLab<SecurityCopilotRequest, SecurityCopilotResponse> {

    private final PipelineOrchestrator orchestrator;
    private final AILabFactory labFactory;
    private final ObjectMapper objectMapper;
    private final SecurityCopilotVectorService vectorService;

    private final ConcurrentHashMap<String, DiagnosisSession> activeSessions = new ConcurrentHashMap<>();

    public SecurityCopilotLab(io.opentelemetry.api.trace.Tracer tracer,
                              PipelineOrchestrator orchestrator, AILabFactory labFactory,
                              ObjectMapper objectMapper,
                              SecurityCopilotVectorService vectorService) {
        super(tracer, "SecurityCopilot", "3.0", LabSpecialization.SECURITY_INTELLIGENCE);
        this.orchestrator = orchestrator;
        this.labFactory = labFactory;
        this.objectMapper = objectMapper;
        this.vectorService = vectorService;
            }

    @Override
    public boolean supportsStreaming() {
        return true;
    }

    @Override
    protected SecurityCopilotResponse doProcess(SecurityCopilotRequest request) throws Exception {
        return doProcessAsync(request).block();
    }

    @Override
    protected Mono<SecurityCopilotResponse> doProcessAsync(SecurityCopilotRequest request) {
                long startTime = System.currentTimeMillis();

        try {
            vectorService.storeSecurityAnalysisRequest(request);
        } catch (Exception e) {
            log.error("벡터 저장소 요청 저장 실패", e);
        }

        return orchestrator.execute(request, SecurityCopilotResponse.class)
                .doOnSuccess(response -> {
                    long endTime = System.currentTimeMillis();

                    try {
                        vectorService.storeSecurityAnalysisResult(request, (SecurityCopilotResponse) response);
                    } catch (Exception e) {
                        log.error("벡터 저장소 결과 저장 실패", e);
                    }
                })
                .doOnError(error -> {
                    log.error("[DIAGNOSIS] SecurityCopilot 진단 처리 실패: {}", error.getMessage(), error);
                });
    }

    @Override
    protected Flux<String> doProcessStream(SecurityCopilotRequest request) {
        
        String sessionId = "unified-" + System.currentTimeMillis();
        DiagnosisSession session = new DiagnosisSession(sessionId, request);
        activeSessions.put(sessionId, session);

        return executeUnifiedPipelineStream(session)
                .doOnTerminate(() -> {
                    activeSessions.remove(sessionId);
                                    });
    }

    private Flux<String> executeUnifiedPipelineStream(DiagnosisSession session) {
        String sessionId = session.getSessionId();
        SecurityCopilotRequest request = session.getRequest();

        Flux<String> sessionStream = Flux.just("SESSION_ID:" + sessionId)
                .doOnNext(msg -> log.info("[PARALLEL-{}] 세션 ID 전송: {}", sessionId, msg));
        
        Map<String, Flux<String>> labStreams = createLabStreams(request);

        LabStreamMerger merger = new LabStreamMerger();
        LabStreamMerger.MergeResult mergeResult = merger.mergeLabStreams(labStreams);

        Mono<SecurityAnalysisResult> analysisResultMono = mergeResult.waitForAllDiagnosis()
                .doOnNext(diagnosisResults -> {
                    
                                        diagnosisResults.forEach((lab, json) -> {
                                            });
                })
                .map(diagnosisResults -> {
                                        diagnosisResults.forEach((lab, json) -> {

                        if (!isValidJson(json)) {
                            log.error("[{}] JSON이 잘렸습니다! 끝부분: {}",
                                    lab, json.length() > 100 ? json.substring(json.length() - 100) : json);
                        }
                    });

                    return createAnalysisResultFromDiagnosis(diagnosisResults, request);
                })
                .cache(); 

        Flux<String> comprehensiveAnalysis = analysisResultMono.flatMapMany(analysisResult ->
                        executeComprehensiveAnalysisWithoutStreaming(analysisResult, request)
                );

        return Flux.concat(
                sessionStream,
                mergeResult.getMergedStream(),
                comprehensiveAnalysis
        ).doOnError(error -> {
            log.error("스트림 처리 중 오류", error);
        });
    }

    private boolean isValidJson(String json) {
        if (json == null || json.isEmpty()) return false;
        json = json.trim();
        return (json.startsWith("{") && json.endsWith("}")) ||
                (json.startsWith("[") && json.endsWith("]"));
    }

    private Flux<String> executeComprehensiveAnalysisWithoutStreaming(SecurityAnalysisResult analysisResult, SecurityCopilotRequest originalRequest) {
        this.validateLabResults(analysisResult);

        SecurityCopilotContext context = this.createComprehensiveAnalysisContext(
                originalRequest, analysisResult);

        AIRequest<SecurityCopilotContext> aiRequest = createComprehensiveAnalysisAIRequest(originalRequest, context, analysisResult);
        aiRequest.withStreaming(true);

        AtomicReference<StringBuilder> markerBuffer = new AtomicReference<>(new StringBuilder());
        AtomicReference<StringBuilder> jsonBuffer = new AtomicReference<>(new StringBuilder());
        AtomicBoolean markerDetected = new AtomicBoolean(false);

        Flux<String> stringFlux = orchestrator.executeStream(aiRequest)
                .map(obj -> obj != null ? obj.toString() : "");

        return stringFlux
                .handle((String chunkStr, SynchronousSink<String> sink) -> {
                    
                    if (markerDetected.get()) {
                        jsonBuffer.get().append(chunkStr);
                        
                        return;
                    }

                    StringBuilder buffer = markerBuffer.get();
                    buffer.append(chunkStr);

                    int markerIndex = buffer.toString().indexOf("###FINAL_RESPONSE###");
                    if (markerIndex != -1) {
                        markerDetected.set(true);

                        if (markerIndex > 0) {
                            String beforeMarker = buffer.substring(0, markerIndex);
                            sink.next(beforeMarker);
                        }

                        if (markerIndex + 20 < buffer.length()) {
                            jsonBuffer.get().append(buffer.substring(markerIndex + 20));
                        }

                        buffer.setLength(0);
                        return;
                    }

                    if (buffer.length() > 30) {
                        int sendLength = buffer.length() - 30;
                        String toSend = buffer.substring(0, sendLength);
                        buffer.delete(0, sendLength);

                        sink.next(toSend);
                    }
                })
                .concatWith(
                        Flux.defer(() -> {
                            
                            List<String> finalItems = new ArrayList<>();

                            if (!markerDetected.get() && markerBuffer.get().length() > 0) {
                                finalItems.add(markerBuffer.get().toString());
                            }

                            try {
                                
                                SecurityCopilotResponse aiResponse = null;

                                if (markerDetected.get()) {
                                    String rawJson = jsonBuffer.get().toString();
                                    String comprehensiveJson = cleanJsonString(rawJson);

                                    if (!comprehensiveJson.isEmpty()) {
                                        try {
                                            aiResponse = objectMapper.readValue(
                                                    comprehensiveJson,
                                                    SecurityCopilotResponse.class
                                            );
                                        } catch (Exception e) {
                                            log.error("종합 분석 JSON 파싱 실패", e);
                                        }
                                    }
                                }

                                SecurityCopilotResponse finalResponse = createFinalSecurityCopilotResponse(
                                        analysisResult,      
                                        aiResponse,          
                                        originalRequest
                                );

                                String json = objectMapper.writeValueAsString(finalResponse);
                                finalItems.add("###FINAL_RESPONSE###" + json);

                            } catch (Exception e) {
                                log.error("최종 응답 생성 실패", e);

                                try {
                                    SecurityCopilotResponse errorResponse = createErrorResponse(originalRequest, e);
                                    String errorJson = objectMapper.writeValueAsString(errorResponse);
                                    finalItems.add("###FINAL_RESPONSE###" + errorJson);
                                } catch (Exception jsonError) {
                                    finalItems.add("###FINAL_RESPONSE###{}");
                                }
                            }

                            return Flux.fromIterable(finalItems);
                        })
                );
    }

    private SecurityCopilotResponse createFinalSecurityCopilotResponse(
            SecurityAnalysisResult labAnalysisResult,
            SecurityCopilotResponse comprehensiveAIResponse,
            SecurityCopilotRequest request) {

        String sessionId = labAnalysisResult.getSessionId();

        SecurityCopilotResponse response  =
                SecurityCopilotResponse.builder()
                        .analysisId(sessionId)
                        .originalQuery(request.getSecurityQuery()).build();

        StudioQueryResponse studioQueryResult = labAnalysisResult.getStudioQueryResult();
        RiskAssessmentResponse riskAssessmentResult = labAnalysisResult.getRiskAssessmentResult();
        PolicyResponse policyGenerationResult = labAnalysisResult.getPolicyGenerationResult();

        response.setStructureAnalysis(studioQueryResult != null ? studioQueryResult : "권한 구조 분석 결과 없음");
        response.setRiskAnalysis(riskAssessmentResult != null ? riskAssessmentResult : "위험 평가 결과 없음");
        response.setActionPlan(policyGenerationResult != null ? policyGenerationResult : "정책 생성 결과 없음");
        response.setOriginalQuery(request.getSecurityQuery());

        if (comprehensiveAIResponse != null) {
            response.setRecommendationSummary(comprehensiveAIResponse.getRecommendationSummary());
            response.setOverallSecurityScore(comprehensiveAIResponse.getOverallSecurityScore());
            response.setRiskLevel(comprehensiveAIResponse.getRiskLevel());
            response.setCategoryScores(comprehensiveAIResponse.getCategoryScores());
            response.setComplianceData(comprehensiveAIResponse.getComplianceData());
            response.setRelationshipAnalysis(comprehensiveAIResponse.getRelationshipAnalysis());
            response.setIntegratedVisualizationData(comprehensiveAIResponse.getIntegratedVisualizationData());
            response.setMultiPerspectiveInsights(comprehensiveAIResponse.getMultiPerspectiveInsights());
            response.setActionPriorities(comprehensiveAIResponse.getActionPriorities());
            response.setPredictiveAnalysis(comprehensiveAIResponse.getPredictiveAnalysis());
        } else {
            
            response.setRecommendationSummary("AI 종합 분석 결과를 기반으로 한 권장사항");
            response.setOverallSecurityScore(calculateOverallScore(labAnalysisResult));
            response.setRiskLevel(calculateRiskLevel(riskAssessmentResult.riskScore()));
        }

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("sessionId", sessionId);
        metadata.put("labResults", labAnalysisResult);
        metadata.put("comprehensiveAnalysisAvailable", comprehensiveAIResponse != null);
        response.setMetadata(metadata);

        long executionTime = System.currentTimeMillis() -
                Long.parseLong(sessionId.substring(sessionId.lastIndexOf("-") + 1));
        response.setExecutionTimeMs(executionTime);

        return response;
    }

    private SecurityCopilotResponse createDefaultResponse(
            SecurityAnalysisResult analysisResult,
            SecurityCopilotRequest request) {

        return createFinalSecurityCopilotResponse(analysisResult, null, request);
    }

    private SecurityCopilotResponse createErrorResponse(
            SecurityCopilotRequest request,
            Exception error) {

        return SecurityCopilotResponse.builder()
                .analysisId("error-" + System.currentTimeMillis())
                .originalQuery(request.getSecurityQuery())
                .recommendationSummary("분석 중 오류가 발생했습니다: " + error.getMessage())
                .overallSecurityScore(0.0)
                .riskLevel("UNKNOWN")
                .status("ERROR")
                .completedAt(LocalDateTime.now())
                .errors(Map.of("error", error.getMessage()))
                .build();
    }

    private void validateLabResults(SecurityAnalysisResult analysisResult) {
        
        Map<String, Object> labResults = analysisResult.getLabResults();

        Object studioResult = labResults.get("StudioQuery");
        if (studioResult instanceof StudioQueryResponse studioResponse) {
                    }

        Object riskResult = labResults.get("RiskAssessment");
        if (riskResult instanceof RiskAssessmentResponse riskResponse) {
                    }

        Object policyResult = labResults.get("PolicyGeneration");
        if (policyResult instanceof PolicyResponse policyResponse) {
                    }
    }

    private SecurityCopilotContext createComprehensiveAnalysisContext(
            SecurityCopilotRequest originalRequest,
            SecurityAnalysisResult analysisResult) {

        SecurityCopilotContext context = new SecurityCopilotContext(
                originalRequest.getUserId(),
                analysisResult.getSessionId()
        );

        String orgId = context.getOrganizationId();
        if (orgId == null || orgId.trim().isEmpty()) {
            orgId = "default-org";
        }

        context.setSecurityQuery(originalRequest.getSecurityQuery());

        Map<String, Object> labResults = analysisResult.getLabResults();

        Object studioResult = labResults.get("StudioQuery");
        if (studioResult instanceof StudioQueryResponse studioResponse) {
            context.addSecurityMetadata("permissionStructure", studioResponse);

            if (studioResponse.getVisualizationData() != null) {
                context.addSecurityMetadata("networkNodes", studioResponse.getVisualizationData().getNodes());
                context.addSecurityMetadata("networkEdges", studioResponse.getVisualizationData().getEdges());
            }

            context.addSecurityMetadata("analysisResults", studioResponse.getAnalysisResults());
        }

        Object riskResult = labResults.get("RiskAssessment");
        if (riskResult instanceof RiskAssessmentResponse riskResponse) {
            context.addSecurityMetadata("riskAssessment", riskResponse);
            context.addSecurityMetadata("trustScore", riskResponse.trustScore());
            context.addSecurityMetadata("riskFactors", riskResponse.getAssessment());
        }

        Object policyResult = labResults.get("PolicyGeneration");
        if (policyResult instanceof PolicyResponse policyResponse) {
            context.addSecurityMetadata("policyData", policyResponse);
            context.addSecurityMetadata("policyRules", policyResponse.getAppliedRules());
            context.addSecurityMetadata("policyConfidence", policyResponse.getPolicyConfidenceScore());
        }

        return context;
    }

    private String calculateRiskLevel(double score) {
        if (score >= 80) return "LOW";
        if (score >= 60) return "MEDIUM";
        if (score >= 40) return "HIGH";
        return "CRITICAL";
    }

    private Map<String, Flux<String>> createLabStreams(SecurityCopilotRequest request) {
        Map<String, Flux<String>> streams = new LinkedHashMap<>();
        String currentThread = Thread.currentThread().getName();
        long startTime = System.currentTimeMillis();

        List<String> labNames = List.of("RiskAssessment", "StudioQuery", "PolicyGeneration");
        
        for (String labName : labNames) {
            Flux<String> labStream = Flux.defer(() -> executeLabStream(request, labName))

                    .cache();

            addLabStream(streams, labName, labStream, startTime);
        }

                return streams;
    }

    private Flux<String> executeLabStream(SecurityCopilotRequest request, String labName) {
        return switch (labName) {
            case "StudioQuery" -> executeLab(
                    StudioQueryLab.class,
                    labName,
                    convertToStudioQueryRequest(request)
            )
                    .doOnComplete(() -> log.info("completed" + labName));
            case "RiskAssessment" -> executeLab(
                    RiskAssessmentLab.class,
                    labName,
                    createRiskAssessmentRequest(request)
            ).doOnComplete(() -> log.info("completed" + labName));
            case "PolicyGeneration" -> executeLab(
                    AdvancedPolicyGenerationLab.class,
                    labName,
                    new PolicyGenerationRequest(request.getSecurityQuery(), null)
            ).doOnComplete(() -> log.info("completed" + labName));
            default -> Flux.just("알 수 없는 Lab: " + labName);
        };
    }

    private <T, R, L extends AbstractAILab<T, R>> Flux<String> executeLab(
            Class<L> labClass,
            String labName,
            T labRequest) {

        return labFactory.getLab(labClass)
                .map(lab -> {
                    if (lab.supportsStreaming()) {
                                                return lab.processStream(labRequest);
                    } else {
                        return lab.processAsync(labRequest)
                                .flux()
                                .map(result -> {
                                    try {
                                        return objectMapper.writeValueAsString(result);
                                    } catch (Exception e) {
                                        log.error("{} 결과 직렬화 실패", labName, e);
                                        return "" + labName + " 분석 실패";
                                    }
                                });
                    }
                })
                .orElse(Flux.just("" + labName + " Lab을 찾을 수 없습니다."));
    }

    private void addLabStream(Map<String, Flux<String>> streams, String labName,
                              Flux<String> labStream, long startTime) {
        String shortName = getShortName(labName);

        Flux<String> instrumentedStream = labStream
                .doOnSubscribe(sub ->
                        log.info("[PARALLEL-{}] {} Lab 구독 시작 - 스레드: {} - 시간: {}ms",
                                shortName, labName, Thread.currentThread().getName(),
                                System.currentTimeMillis() - startTime))
                .doOnNext(msg ->
                        log.debug("[PARALLEL-{}] 메시지: {}", shortName,
                                msg.length() > 30 ? msg.substring(0, 30) + "..." : msg))
                .doOnComplete(() ->
                        log.info("[PARALLEL-{}] {} Lab 완료 - 스레드: {} - 시간: {}ms",
                                shortName, labName, Thread.currentThread().getName(),
                                System.currentTimeMillis() - startTime))
                .doOnError(error ->
                        log.error("[PARALLEL-{}] {} Lab 오류 - 스레드: {}",
                                shortName, labName, Thread.currentThread().getName(), error));

        streams.put(labName, instrumentedStream);
    }

    private String getShortName(String labName) {
        return switch (labName) {
            case "StudioQuery" -> "STUDIO";
            case "RiskAssessment" -> "RISK";
            case "PolicyGeneration" -> "POLICY";
            default -> labName.toUpperCase();
        };
    }

    private RiskAssessmentRequest createRiskAssessmentRequest(SecurityCopilotRequest request) {
        RiskAssessmentContext context = new RiskAssessmentContext(
                request.getUserId(),
                "session-" + System.currentTimeMillis(),
                SecurityLevel.HIGH,
                AuditRequirement.DETAILED
        );
        return new RiskAssessmentRequest(context, null);
    }

    private double calculateOverallScore(SecurityAnalysisResult labResults) {
        if (labResults.getLabResults().isEmpty()) {
            return 0.0;
        }

        double totalScore = 0.0;
        int validLabCount = 0;

        for (Map.Entry<String, Object> entry : labResults.getLabResults().entrySet()) {
            if (isLabResultSuccessful(entry.getValue())) {
                validLabCount++;
                totalScore += 85.0; 
            }
        }

        return validLabCount > 0 ? totalScore / validLabCount : 0.0;
    }

    private AIRequest<SecurityCopilotContext> createComprehensiveAnalysisAIRequest(
            SecurityCopilotRequest request,
            SecurityCopilotContext context,
            SecurityAnalysisResult labResults) {

        AIRequest<SecurityCopilotContext> aiRequest = new AIRequest<>(
                context,
                "securityCopilotStreaming",
                request.getOrganizationId()
        );

        aiRequest.withParameter("securityQuery", request.getSecurityQuery());

        aiRequest.withParameter("requestType", "comprehensive_analysis");
        aiRequest.withParameter("outputFormat", "structured_json"); 

        aiRequest.withParameter("requiredFields", Map.of(
                "structureAnalysis", "권한 구조 분석 결과",
                "riskAnalysis", "위험 평가 분석 결과",
                "actionPlan", "조치 계획 및 정책 제안",
                "overallSecurityScore", "전체 보안 점수 (0-100)",
                "recommendationSummary", "종합 권장사항 요약",
                "categoryScores", Map.of(
                        "permissionStructure", "권한 구조 점수",
                        "riskAssessment", "위험 평가 점수",
                        "policyEfficiency", "정책 효율성 점수"
                ),
                "metadata", Map.of(
                        "recommendations", "권장사항 리스트",
                        "criticalFindings", "중요 발견사항 리스트",
                        "complianceStatus", "컴플라이언스 상태"
                )
        ));

        Map<String, Object> structuredLabResults = new HashMap<>();
        labResults.getLabResults().forEach((labName, result) -> {
            structuredLabResults.put(labName, Map.of(
                    "status", isLabResultSuccessful(result) ? "SUCCESS" : "FAILED",
                    "data", result != null ? result.toString() : "",
                    "score", calculateCategoryScore(labResults, labName)
            ));
        });
        aiRequest.withParameter("labResults", structuredLabResults);

        aiRequest.withParameter("language", "korean");
        aiRequest.withParameter("responseLanguage", "korean");

                return aiRequest;
    }

    private String cleanJsonString(String rawJson) {
        if (rawJson == null || rawJson.isEmpty()) {
            return rawJson;
        }

        String cleaned = rawJson;

        if (cleaned.contains("```")) {
            
            Pattern codeBlockPattern = Pattern.compile("```(?:json)?\\s*([\\s\\S]*?)```", Pattern.MULTILINE);
            Matcher matcher = codeBlockPattern.matcher(cleaned);

            if (matcher.find()) {
                
                cleaned = matcher.group(1).trim();
                            } else {
                
                cleaned = cleaned.replaceAll("```(?:json)?", "").replaceAll("```", "");
            }
        }

        cleaned = cleaned.replaceAll("`", "");

        cleaned = cleaned.trim();

        if (cleaned.length() > 0 && cleaned.charAt(0) == '\uFEFF') {
            cleaned = cleaned.substring(1);
        }
        cleaned = cleaned.replaceAll("[\\x00-\\x1F\\x7F]", " "); 

        int jsonStart = findJsonStart(cleaned);
        if (jsonStart > 0) {
                        cleaned = cleaned.substring(jsonStart);
        }

        int jsonEnd = findJsonEnd(cleaned);
        if (jsonEnd > 0 && jsonEnd < cleaned.length()) {
                        cleaned = cleaned.substring(0, jsonEnd);
        }

        cleaned = cleaned.replaceAll("\\\\\"", "\"");

        if (!isValidJsonStructure(cleaned)) {
            log.error("종합 분석 JSON 정제 실패. 구조가 유효하지 않음");

            Pattern jsonObjectPattern = Pattern.compile("\\{[^{}]*(?:\\{[^{}]*\\}[^{}]*)*\\}", Pattern.DOTALL);
            Matcher objMatcher = jsonObjectPattern.matcher(rawJson);

            if (objMatcher.find()) {
                cleaned = objMatcher.group();
                            } else {
                log.error("JSON 객체 추출 완전 실패");
                return "";
            }
        }

                return cleaned;
    }

    private int findJsonStart(String text) {
        int braceIndex = text.indexOf('{');
        int bracketIndex = text.indexOf('[');

        if (braceIndex == -1 && bracketIndex == -1) {
            return -1;
        }

        if (braceIndex == -1) return bracketIndex;
        if (bracketIndex == -1) return braceIndex;

        return Math.min(braceIndex, bracketIndex);
    }

    private int findJsonEnd(String text) {
        int depth = 0;
        boolean inString = false;
        char prevChar = 0;
        int lastClosingIndex = -1;

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);

            if (!inString) {
                if (c == '"' && prevChar != '\\') {
                    inString = true;
                } else if (c == '{' || c == '[') {
                    depth++;
                } else if (c == '}' || c == ']') {
                    depth--;
                    if (depth == 0) {
                        lastClosingIndex = i + 1;
                        break; // 첫 번째 완성된 JSON 객체/배열에서 중단
                    }
                }
            } else {
                if (c == '"' && prevChar != '\\') {
                    inString = false;
                }
            }
            prevChar = c;
        }

        return lastClosingIndex;
    }

    private boolean isValidJsonStructure(String json) {
        if (json == null || json.isEmpty()) {
            return false;
        }

        json = json.trim();

        boolean isObject = json.startsWith("{") && json.endsWith("}");
        boolean isArray = json.startsWith("[") && json.endsWith("]");

        if (!isObject && !isArray) {
            return false;
        }

        int depth = 0;
        boolean inString = false;
        char prevChar = 0;

        for (char c : json.toCharArray()) {
            if (!inString) {
                if (c == '"' && prevChar != '\\') {
                    inString = true;
                } else if (c == '{' || c == '[') {
                    depth++;
                } else if (c == '}' || c == ']') {
                    depth--;
                    if (depth < 0) {
                        return false; // 닫는 괄호가 더 많음
                    }
                }
            } else {
                if (c == '"' && prevChar != '\\') {
                    inString = false;
                }
            }
            prevChar = c;
        }

        return depth == 0;
    }

    private double calculateCategoryScore(SecurityAnalysisResult labResults, String labName) {
        Object result = labResults.getLabResults().get(labName);

        if (result != null && isLabResultSuccessful(result)) {
            
            double baseScore = 70.0;

            String resultText = result.toString();
            if (resultText.length() > 500) {
                baseScore += 10.0; 
            }
            if (resultText.contains("성공") || resultText.contains("완료")) {
                baseScore += 5.0;
            }
            if (resultText.contains("위험") || resultText.contains("주의")) {
                baseScore -= 5.0; 
            }

            return Math.min(Math.max(baseScore, 0), 100); 
        }

        return 30.0;
    }

    private StudioQueryRequest convertToStudioQueryRequest(SecurityCopilotRequest request) {
        return StudioQueryRequest.quickQuery(
                request.getSecurityQuery(),
                "SECURITY_ANALYSIS",
                request.getUserId()
        );
    }

    private boolean isLabResultSuccessful(Object result) {
        if (result == null) return false;
        String resultStr = result.toString().toLowerCase();
        return !resultStr.contains("실패") && !resultStr.contains("오류") &&
                !resultStr.contains("없음") && !resultStr.isEmpty();
    }

    @Getter
    private static class DiagnosisSession {
        private final String sessionId;
        private final SecurityCopilotRequest request;
        private final long startTime;
        private SecurityAnalysisResult labResults;
        private SecurityCopilotResponse finalResponse;
        private volatile String status = "STARTED"; 

        public DiagnosisSession(String sessionId, SecurityCopilotRequest request) {
            this.sessionId = sessionId;
            this.request = request;
            this.startTime = System.currentTimeMillis();
        }

        public void setLabResults(SecurityAnalysisResult labResults) {
            this.labResults = labResults;
            this.status = "LABS_COMPLETED"; 
        }

        public void setFinalResponse(SecurityCopilotResponse response) {
            this.finalResponse = response;
            this.status = "COMPLETED"; 
        }

        public String getStatus() { 
            return this.status;
        }
    }

    private SecurityAnalysisResult createAnalysisResultFromDiagnosis(
            Map<String, String> diagnosisResults, SecurityCopilotRequest request) {

        String sessionId = "analysis-" + System.currentTimeMillis();
        SecurityAnalysisResult analysisResult = new SecurityAnalysisResult(sessionId);

        try {
            
            if (diagnosisResults.containsKey("StudioQuery")) {
                String studioJson = diagnosisResults.get("StudioQuery");

                String cleanedJson = cleanLabDiagnosisJson(studioJson, "StudioQuery");

                if (!cleanedJson.isEmpty()) {
                    try {
                        StudioQueryResponse studioResponse = objectMapper.readValue(cleanedJson, StudioQueryResponse.class);
                        analysisResult.setStudioQueryCompleted(true);
                        analysisResult.setStudioQueryResult(studioResponse);
                                            } catch (Exception e) {
                        log.error("StudioQuery JSON 파싱 실패: {}", e.getMessage());
                                            }
                }
            }

            if (diagnosisResults.containsKey("RiskAssessment")) {
                String riskJson = diagnosisResults.get("RiskAssessment");
                String cleanedJson = cleanLabDiagnosisJson(riskJson, "RiskAssessment");

                if (!cleanedJson.isEmpty()) {
                    try {
                        RiskAssessmentResponse riskResponse = objectMapper.readValue(cleanedJson, RiskAssessmentResponse.class);
                        analysisResult.setRiskAssessmentCompleted(true);
                        analysisResult.setRiskAssessmentResult(riskResponse);
                                            } catch (Exception e) {
                        log.error("RiskAssessment JSON 파싱 실패: {}", e.getMessage());
                                            }
                }
            }

            if (diagnosisResults.containsKey("PolicyGeneration")) {
                String policyJson = diagnosisResults.get("PolicyGeneration");
                String cleanedJson = cleanLabDiagnosisJson(policyJson, "PolicyGeneration");

                if (!cleanedJson.isEmpty()) {
                    try {
                        PolicyResponse policyResponse = objectMapper.readValue(cleanedJson, PolicyResponse.class);
                        analysisResult.setPolicyGenerationCompleted(true);
                        analysisResult.setPolicyGenerationResult(policyResponse);
                                            } catch (Exception e) {
                        log.error("PolicyGeneration JSON 파싱 실패: {}", e.getMessage());
                                            }
                }
            }

        } catch (Exception e) {
            log.error("[DIAGNOSIS-ANALYSIS] 진단 결과 파싱 실패", e);
            return new SecurityAnalysisResult(sessionId);
        }

        return analysisResult;
    }

    private String cleanLabDiagnosisJson(String rawJson, String labName) {
        if (rawJson == null || rawJson.isEmpty()) {
            return "";
        }

        String cleaned = cleanJsonString(rawJson);

        if (cleaned.isEmpty()) {
            log.warn("[{}] Lab 진단 결과 JSON 정제 실패", labName);
        }

        return cleaned;
    }

    public void learnFromFeedback(SecurityCopilotRequest request, SecurityCopilotResponse response, String feedback) {
        try {

            vectorService.storeSecurityAnalysisResult(request, response);
            
                    } catch (Exception e) {
            log.error("[SecurityCopilotLab] 피드백 학습 실패", e);
        }
    }

}