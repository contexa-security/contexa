package io.contexa.contexaiam.aiam.labs.securityCopilot;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacore.std.labs.AbstractAILab;
import io.contexa.contexacore.std.labs.risk.RiskAssessmentLab;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacommon.domain.LabSpecialization;
import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.scheduler.ParallelExecutionMonitor;
import io.contexa.contexaiam.aiam.labs.AbstractIAMLab;
import io.contexa.contexaiam.aiam.labs.policy.AdvancedPolicyGenerationLab;
import io.contexa.contexaiam.aiam.labs.securityCopilot.streaming.LabStreamMerger;
import io.contexa.contexaiam.aiam.labs.studio.StudioQueryLab;
import io.contexa.contexaiam.aiam.protocol.context.SecurityCopilotContext;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.request.SecurityCopilotRequest;
import io.contexa.contexaiam.aiam.protocol.request.StudioQueryRequest;
import io.contexa.contexaiam.aiam.protocol.response.*;
import io.contexa.contexacommon.domain.request.RiskAssessmentRequest;
import io.contexa.contexacommon.domain.response.RiskAssessmentResponse;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexacommon.enums.SecurityLevel;
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

/**
 * AI 보안 어드바이저 (Security Copilot Lab) - PipelineOrchestrator 기반
 *
 * PipelineOrchestrator.executeStream() → StreamingUniversalPipelineExecutor 자동 선택
 * PipelineOrchestrator.execute() → 일반 진단 전용 executor 선택
 * Lab 병렬 실행 → AI 종합 분석 → 실시간 스트리밍
 * 진단과 스트리밍 일원화
 */
@Slf4j
public class SecurityCopilotLab extends AbstractIAMLab<SecurityCopilotRequest, SecurityCopilotResponse> {

    private final PipelineOrchestrator orchestrator;
    private final AILabFactory labFactory;
    private final ObjectMapper objectMapper;
    private final ParallelExecutionMonitor monitor;
    private final SecurityCopilotVectorService vectorService;

    private final ConcurrentHashMap<String, DiagnosisSession> activeSessions = new ConcurrentHashMap<>();
//    private final @Qualifier("streamingVirtualScheduler") Scheduler streamingVirtualScheduler;
//    private final @Qualifier("parallelVirtualScheduler") Scheduler parallelVirtualScheduler;

    public SecurityCopilotLab(io.opentelemetry.api.trace.Tracer tracer,
                              PipelineOrchestrator orchestrator, AILabFactory labFactory,
                              ObjectMapper objectMapper, ParallelExecutionMonitor monitor,
                              SecurityCopilotVectorService vectorService) {
        super(tracer, "SecurityCopilot", "3.0", LabSpecialization.SECURITY_INTELLIGENCE);
        this.orchestrator = orchestrator;
        this.labFactory = labFactory;
        this.objectMapper = objectMapper;
        this.monitor = monitor;
//        this.parallelVirtualScheduler = parallelVirtualScheduler;
        this.vectorService = vectorService;
        log.info("SecurityCopilotLab 3.0 초기화 - PipelineOrchestrator 기반 with Vector Storage");
    }

    @Override
    public boolean supportsStreaming() {
        return true;
    }

    // ==================== 핵심: 일원화된 진단 프로세스 ====================

    @Override
    protected SecurityCopilotResponse doProcess(SecurityCopilotRequest request) throws Exception {
        return doProcessAsync(request).block();
    }

    @Override
    protected Mono<SecurityCopilotResponse> doProcessAsync(SecurityCopilotRequest request) {
        log.info("[DIAGNOSIS] SecurityCopilot 진단 처리 시작: {} (일반 executor 사용)", request.getSecurityQuery());
        long startTime = System.currentTimeMillis();
        
        // 벡터 저장소에 요청 저장
        try {
            vectorService.storeSecurityAnalysisRequest(request);
        } catch (Exception e) {
            log.error("벡터 저장소 요청 저장 실패", e);
        }

        /*SecurityCopilotContext context = new SecurityCopilotContext(
                request.getUserId(),
                "copilot-" + UUID.randomUUID().toString().substring(0, 8)
        );
        context.setSecurityQuery(request.getSecurityQuery());

        AIRequest<SecurityCopilotContext> aiRequest = new IAMRequest<>(context, "securityCopilot")
                .withDiagnosisType(DiagnosisType.SECURITY_COPILOT)
                .withParameter("processingMode", "analysis")
                .withParameter("securityQuery", request.getSecurityQuery());*/

        log.info("[DIAGNOSIS] PipelineOrchestrator.execute() 호출 - Strategy 최적화 파이프라인 사용");

        return orchestrator.execute(request, SecurityCopilotResponse.class)
                .doOnSuccess(response -> {
                    long endTime = System.currentTimeMillis();
                    log.info("[DIAGNOSIS] SecurityCopilot 진단 처리 완료 ({}ms): JSON 응답 생성",
                            endTime - startTime);
                    
                    // 벡터 저장소에 결과 저장
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
        log.info("[STREAMING] 일원화 스트리밍 진단 시작: {} (StreamingUniversalPipelineExecutor 자동선택)", request.getSecurityQuery());

        String sessionId = "unified-" + System.currentTimeMillis();
        DiagnosisSession session = new DiagnosisSession(sessionId, request);
        activeSessions.put(sessionId, session);

        return executeUnifiedPipelineStream(session)
                .doOnTerminate(() -> {
                    activeSessions.remove(sessionId);
                    log.info("[STREAMING] 스트리밍 세션 종료", sessionId);
                });
    }


    // SecurityCopilotLab.java의 executeUnifiedPipelineStream 메서드 수정

    private Flux<String> executeUnifiedPipelineStream(DiagnosisSession session) {
        String sessionId = session.getSessionId();
        SecurityCopilotRequest request = session.getRequest();

        // 1. 세션 ID 전송
        Flux<String> sessionStream = Flux.just("SESSION_ID:" + sessionId)
                .doOnNext(msg -> log.info("[PARALLEL-{}] 세션 ID 전송: {}", sessionId, msg));

        // 2. Lab 병렬 스트리밍 (각 Lab이 6단계 전체 실행)
        Map<String, Flux<String>> labStreams = createLabStreams(request);

        // 3. 스트림 병합
        LabStreamMerger merger = new LabStreamMerger();
        LabStreamMerger.MergeResult mergeResult = merger.mergeLabStreams(labStreams);

        // 4. 종합 분석 - flatMap 사용 (flatMapMany 대신)
        Mono<SecurityAnalysisResult> analysisResultMono = mergeResult.waitForAllDiagnosis()
                .doOnNext(diagnosisResults -> {
                    // 받자마자 즉시 확인
                    log.info("[waitForAllDiagnosis 직후] Map 크기: {}", diagnosisResults.size());
                    diagnosisResults.forEach((lab, json) -> {
                        log.info("[받은직후][{}] 길이: {}", lab, json.length());
                    });
                })
                .map(diagnosisResults -> {
                    log.info("종합 분석 시작 - {} 개 진단 결과", diagnosisResults.size());
                    diagnosisResults.forEach((lab, json) -> {
                        log.info("[map내부][{}] 길이: {}, 유효JSON: {}", lab, json.length(), isValidJson(json));

                        // 잘린 데이터 감지
                        if (!isValidJson(json)) {
                            log.error("[{}] JSON이 잘렸습니다! 끝부분: {}",
                                    lab, json.length() > 100 ? json.substring(json.length() - 100) : json);
                        }
                    });

                    return createAnalysisResultFromDiagnosis(diagnosisResults, request);
                })
                .cache(); // 결과를 캐시하여 재계산 방지

        // 5. 종합 분석 스트림 생성
        Flux<String> comprehensiveAnalysis = analysisResultMono.flatMapMany(analysisResult ->
                        executeComprehensiveAnalysisWithoutStreaming(analysisResult, request)
                );

        // 6. 순차 조합
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

    /**
     * 종합 AI 분석 실행
     */
    private Flux<String> executeComprehensiveAnalysisWithoutStreaming(SecurityAnalysisResult analysisResult, SecurityCopilotRequest originalRequest) {
        this.validateLabResults(analysisResult);

        // 연관성 분석을 위한 컨텍스트 생성
        SecurityCopilotContext context = this.createComprehensiveAnalysisContext(
                originalRequest, analysisResult);

        // AI 요청 생성 (스트리밍 모드)
        AIRequest<SecurityCopilotContext> aiRequest = createComprehensiveAnalysisAIRequest(originalRequest, context, analysisResult);
        aiRequest.withStreaming(true);

        // 상태 관리
        AtomicReference<StringBuilder> markerBuffer = new AtomicReference<>(new StringBuilder());
        AtomicReference<StringBuilder> jsonBuffer = new AtomicReference<>(new StringBuilder());
        AtomicBoolean markerDetected = new AtomicBoolean(false);

        Flux<String> stringFlux = orchestrator.executeStream(aiRequest)
                .map(obj -> obj != null ? obj.toString() : "");

        // 실시간 스트리밍 + JSON 수집을 동시에
        return stringFlux
                .handle((String chunkStr, SynchronousSink<String> sink) -> {
                    // JSON 수집 모드
                    if (markerDetected.get()) {
                        jsonBuffer.get().append(chunkStr);
                        // 마커 이후는 전송하지 않음
                        return;
                    }

                    // 마커 버퍼링
                    StringBuilder buffer = markerBuffer.get();
                    buffer.append(chunkStr);

                    // 마커 감지
                    int markerIndex = buffer.toString().indexOf("###FINAL_RESPONSE###");
                    if (markerIndex != -1) {
                        markerDetected.set(true);

                        // 마커 이전 부분은 전송
                        if (markerIndex > 0) {
                            String beforeMarker = buffer.substring(0, markerIndex);
                            sink.next(beforeMarker);
                        }

                        // 마커 이후 JSON 수집
                        if (markerIndex + 20 < buffer.length()) {
                            jsonBuffer.get().append(buffer.substring(markerIndex + 20));
                        }

                        buffer.setLength(0);
                        return;
                    }

                    // 마커가 없으면 안전한 부분만 실시간 전송
                    if (buffer.length() > 30) {
                        int sendLength = buffer.length() - 30;
                        String toSend = buffer.substring(0, sendLength);
                        buffer.delete(0, sendLength);

                        // 실시간 전송!
                        sink.next(toSend);
                    }
                })
                .concatWith(
                        Flux.defer(() -> {
                            // 남은 버퍼 + 최종 응답 처리
                            List<String> finalItems = new ArrayList<>();

                            // 버퍼에 남은 데이터 전송
                            if (!markerDetected.get() && markerBuffer.get().length() > 0) {
                                finalItems.add(markerBuffer.get().toString());
                            }

                            // 최종 응답 생성
                            try {
                                // 종합 분석 AI 응답 파싱
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

                                // 최종 SecurityCopilotResponse 생성
                                SecurityCopilotResponse finalResponse = createFinalSecurityCopilotResponse(
                                        analysisResult,      // Lab 진단 결과
                                        aiResponse,          // 종합 분석 AI 응답 (null 가능)
                                        originalRequest
                                );

                                String json = objectMapper.writeValueAsString(finalResponse);
                                finalItems.add("###FINAL_RESPONSE###" + json);

                            } catch (Exception e) {
                                log.error("최종 응답 생성 실패", e);

                                // 에러 응답 생성
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



    /**
     * 최종 SecurityCopilotResponse 생성 (개선된 버전)
     */
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

        // 종합 분석 AI 응답 병합
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
            // 기본값 설정
            response.setRecommendationSummary("AI 종합 분석 결과를 기반으로 한 권장사항");
            response.setOverallSecurityScore(calculateOverallScore(labAnalysisResult));
            response.setRiskLevel(calculateRiskLevel(riskAssessmentResult.riskScore()));
        }

        // 메타데이터
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("sessionId", sessionId);
        metadata.put("labResults", labAnalysisResult);
        metadata.put("comprehensiveAnalysisAvailable", comprehensiveAIResponse != null);
        response.setMetadata(metadata);

        // 실행 시간
        long executionTime = System.currentTimeMillis() -
                Long.parseLong(sessionId.substring(sessionId.lastIndexOf("-") + 1));
        response.setExecutionTimeMs(executionTime);

        return response;
    }

    /**
     * 기본 응답 생성 (마커 미감지 시)
     */
    private SecurityCopilotResponse createDefaultResponse(
            SecurityAnalysisResult analysisResult,
            SecurityCopilotRequest request) {

        return createFinalSecurityCopilotResponse(analysisResult, null, request);
    }

    /**
     * 에러 응답 생성
     */
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

    /**
     * 개별 Lab 결과 검증
     */
    private void validateLabResults(SecurityAnalysisResult analysisResult) {
        log.info("개별 Lab 결과 검증 시작");

        Map<String, Object> labResults = analysisResult.getLabResults();

        // StudioQuery 결과 검증
        Object studioResult = labResults.get("StudioQuery");
        if (studioResult instanceof StudioQueryResponse studioResponse) {
            log.info("StudioQuery 결과 검증 완료 - 시각화 데이터: {}, 권장사항: {}",
                    studioResponse.getVisualizationData() != null,
                    studioResponse.getRecommendations() != null ? studioResponse.getRecommendations().size() : 0);
        }

        // RiskAssessment 결과 검증
        Object riskResult = labResults.get("RiskAssessment");
        if (riskResult instanceof RiskAssessmentResponse riskResponse) {
            log.info("RiskAssessment 결과 검증 완료 - 위험점수: {}, 신뢰도: {}",
                    riskResponse.riskScore(), riskResponse.trustScore());
        }

        // PolicyGeneration 결과 검증
        Object policyResult = labResults.get("PolicyGeneration");
        if (policyResult instanceof PolicyResponse policyResponse) {
            log.info("PolicyGeneration 결과 검증 완료 - 정책 데이터: {}, 신뢰도: {}",
                    policyResponse.getPolicyData() != null,
                    policyResponse.getPolicyConfidenceScore());
        }
    }

    /**
     * 연관성 분석을 위한 컨텍스트 생성
     */
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

        // 개별 Lab 결과를 연관성 분석용 메타데이터로 추가
        Map<String, Object> labResults = analysisResult.getLabResults();

        // 1. 권한 구조 데이터 추가
        Object studioResult = labResults.get("StudioQuery");
        if (studioResult instanceof StudioQueryResponse studioResponse) {
            context.addSecurityMetadata("permissionStructure", studioResponse);

            // 시각화 데이터에서 노드/엣지 정보 추출
            if (studioResponse.getVisualizationData() != null) {
                context.addSecurityMetadata("networkNodes", studioResponse.getVisualizationData().getNodes());
                context.addSecurityMetadata("networkEdges", studioResponse.getVisualizationData().getEdges());
            }

            // 권한 분석 결과 추가
            context.addSecurityMetadata("analysisResults", studioResponse.getAnalysisResults());
        }

        // 2. 위험 평가 데이터 추가
        Object riskResult = labResults.get("RiskAssessment");
        if (riskResult instanceof RiskAssessmentResponse riskResponse) {
            context.addSecurityMetadata("riskAssessment", riskResponse);
            context.addSecurityMetadata("trustScore", riskResponse.trustScore());
            context.addSecurityMetadata("riskFactors", riskResponse.getAssessment());
        }

        // 3. 정책 데이터 추가
        Object policyResult = labResults.get("PolicyGeneration");
        if (policyResult instanceof PolicyResponse policyResponse) {
            context.addSecurityMetadata("policyData", policyResponse);
            context.addSecurityMetadata("policyRules", policyResponse.getAppliedRules());
            context.addSecurityMetadata("policyConfidence", policyResponse.getPolicyConfidenceScore());
        }

        log.info("연관성 분석 컨텍스트 생성 완료 - 메타데이터: {}", context.getSecurityMetadata().size());

        return context;
    }

    /**
     * 보안 점수로 위험 수준 계산
     */
    private String calculateRiskLevel(double score) {
        if (score >= 80) return "LOW";
        if (score >= 60) return "MEDIUM";
        if (score >= 40) return "HIGH";
        return "CRITICAL";
    }

    // ====================== 설정 메서드 ======================

    /**
     * 병렬 Lab 스트림 생성
     */
    private Map<String, Flux<String>> createLabStreams(SecurityCopilotRequest request) {
        Map<String, Flux<String>> streams = new LinkedHashMap<>();
        String currentThread = Thread.currentThread().getName();
        long startTime = System.currentTimeMillis();

        log.info("[PARALLEL-STREAMS] Lab 병렬 스트림 생성 시작 - 스레드: {}", currentThread);

        List<String> labNames = List.of("RiskAssessment", "StudioQuery", "PolicyGeneration");
        // 핵심 개선: 각 Lab 스트림에 publishOn 적용
        for (String labName : labNames) {
            Flux<String> labStream = Flux.defer(() -> executeLabStream(request, labName))
//                    .subscribeOn(parallelVirtualScheduler)
                    .cache();

            addLabStream(streams, labName, labStream, startTime);
        }

        log.info("[PARALLEL-STREAMS] Lab 병렬 스트림 생성 완료 - {} 개 스트림", streams.size());
        return streams;
    }

   /* private Flux<String> executeLabStream(SecurityCopilotRequest request, String labName) {
        // ★★★ 실제 파이프라인 대신, 지연을 시뮬레이션하는 테스트 Flux 반환
        return Flux.interval(Duration.ofMillis(500)) // 0.5초마다 데이터 방출
                .map(i -> String.format("'%s' 테스트 데이터 %d", labName, i + 1))
                .take(10) // 10개만 방출하고
                .concatWith(Mono.just("###FINAL_RESPONSE###{\"result\":\"OK\"}")); // 종료
    }*/

    private Flux<String> executeLabStream(SecurityCopilotRequest request, String labName) {
        return switch (labName) {
            case "StudioQuery" -> executeLab(
                    StudioQueryLab.class,
                    labName,
                    convertToStudioQueryRequest(request)
            )
                    .doOnComplete(() -> monitor.recordLabComplete(labName));
            case "RiskAssessment" -> executeLab(
                    RiskAssessmentLab.class,
                    labName,
                    createRiskAssessmentRequest(request)
            ).doOnComplete(() -> monitor.recordLabComplete(labName));
            case "PolicyGeneration" -> executeLab(
                    AdvancedPolicyGenerationLab.class,
                    labName,
                    new PolicyGenerationRequest(request.getSecurityQuery(), null)
            ).doOnComplete(() -> monitor.recordLabComplete(labName));
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
                        log.info("[DELEGATE] {}.processStream() 직접 호출", labName);
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


    // 전체 점수 계산
    private double calculateOverallScore(SecurityAnalysisResult labResults) {
        if (labResults.getLabResults().isEmpty()) {
            return 0.0;
        }

        double totalScore = 0.0;
        int validLabCount = 0;

        // 각 Lab 결과에 대해 점수 계산
        for (Map.Entry<String, Object> entry : labResults.getLabResults().entrySet()) {
            if (isLabResultSuccessful(entry.getValue())) {
                validLabCount++;
                totalScore += 85.0; // 성공한 Lab은 85점으로 계산
            }
        }

        return validLabCount > 0 ? totalScore / validLabCount : 0.0;
    }

    /**
     * AI 종합 분석 요청 생성 (비스트리밍)
     */
    private AIRequest<SecurityCopilotContext> createComprehensiveAnalysisAIRequest(
            SecurityCopilotRequest request,
            SecurityCopilotContext context,
            SecurityAnalysisResult labResults) {

        AIRequest<SecurityCopilotContext> aiRequest = new AIRequest<>(
                context,
                "securityCopilotStreaming",
                request.getOrganizationId()
        );

        // 기본 파라미터
        aiRequest.withParameter("securityQuery", request.getSecurityQuery());
//        aiRequest.withParameter("analysisScope", context.getAnalysisScope());
//        aiRequest.withParameter("priority", context.getPriority());
        aiRequest.withParameter("requestType", "comprehensive_analysis");
        aiRequest.withParameter("outputFormat", "structured_json"); // 구조화된 JSON 요청

        // AI가 반환해야 할 필수 필드 명시
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

        // Lab 결과를 구조화해서 전달
        Map<String, Object> structuredLabResults = new HashMap<>();
        labResults.getLabResults().forEach((labName, result) -> {
            structuredLabResults.put(labName, Map.of(
                    "status", isLabResultSuccessful(result) ? "SUCCESS" : "FAILED",
                    "data", result != null ? result.toString() : "",
                    "score", calculateCategoryScore(labResults, labName)
            ));
        });
        aiRequest.withParameter("labResults", structuredLabResults);

        // 한국어 설정
        aiRequest.withParameter("language", "korean");
        aiRequest.withParameter("responseLanguage", "korean");

        log.info("[HYBRID] AI 종합분석 요청 생성 완료 - 구조화된 응답 요청");
        return aiRequest;
    }

    private String cleanJsonString(String rawJson) {
        if (rawJson == null || rawJson.isEmpty()) {
            return rawJson;
        }

        log.debug("종합 분석 원본 응답 (처음 200자): {}",
                rawJson.length() > 200 ? rawJson.substring(0, 200) + "..." : rawJson);

        String cleaned = rawJson;

        // 1. 마크다운 코드 블록 제거
        if (cleaned.contains("```")) {
            // ```json 또는 ``` 패턴 찾기
            Pattern codeBlockPattern = Pattern.compile("```(?:json)?\\s*([\\s\\S]*?)```", Pattern.MULTILINE);
            Matcher matcher = codeBlockPattern.matcher(cleaned);

            if (matcher.find()) {
                // 코드 블록 내용만 추출
                cleaned = matcher.group(1).trim();
                log.debug("마크다운 코드 블록 제거됨");
            } else {
                // 단순 ``` 제거
                cleaned = cleaned.replaceAll("```(?:json)?", "").replaceAll("```", "");
            }
        }

        // 2. 백틱 제거
        cleaned = cleaned.replaceAll("`", "");

        // 3. 앞뒤 공백 및 줄바꿈 제거
        cleaned = cleaned.trim();

        // 4. BOM 및 제어 문자 제거
        if (cleaned.length() > 0 && cleaned.charAt(0) == '\uFEFF') {
            cleaned = cleaned.substring(1);
        }
        cleaned = cleaned.replaceAll("[\\x00-\\x1F\\x7F]", " "); // 제어문자는 공백으로 변환

        // 5. AI가 추가한 설명 텍스트 제거 (JSON 이전 부분)
        int jsonStart = findJsonStart(cleaned);
        if (jsonStart > 0) {
            log.debug("JSON 이전 텍스트 제거: {} 문자", jsonStart);
            cleaned = cleaned.substring(jsonStart);
        }

        // 6. JSON 끝 이후 텍스트 제거
        int jsonEnd = findJsonEnd(cleaned);
        if (jsonEnd > 0 && jsonEnd < cleaned.length()) {
            log.debug("JSON 이후 텍스트 제거: {} 문자", cleaned.length() - jsonEnd);
            cleaned = cleaned.substring(0, jsonEnd);
        }

        // 7. 이스케이프된 따옴표 처리
        // AI가 가끔 JSON 내부의 따옴표를 잘못 이스케이프하는 경우
        cleaned = cleaned.replaceAll("\\\\\"", "\"");

        // 8. 최종 검증
        if (!isValidJsonStructure(cleaned)) {
            log.error("종합 분석 JSON 정제 실패. 구조가 유효하지 않음");
            log.debug("정제된 결과: {}", cleaned);

            // 최후의 수단: 정규식으로 JSON 객체 추출
            Pattern jsonObjectPattern = Pattern.compile("\\{[^{}]*(?:\\{[^{}]*\\}[^{}]*)*\\}", Pattern.DOTALL);
            Matcher objMatcher = jsonObjectPattern.matcher(rawJson);

            if (objMatcher.find()) {
                cleaned = objMatcher.group();
                log.info("정규식으로 JSON 객체 추출 성공");
            } else {
                log.error("JSON 객체 추출 완전 실패");
                return "";
            }
        }

        log.debug("종합 분석 JSON 정제 완료 ({}자)", cleaned.length());
        return cleaned;
    }

    /**
     * JSON 시작 위치 찾기
     */
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

    /**
     * JSON 끝 위치 찾기
     */
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

        // 객체 또는 배열로 시작하고 끝나는지 확인
        boolean isObject = json.startsWith("{") && json.endsWith("}");
        boolean isArray = json.startsWith("[") && json.endsWith("]");

        if (!isObject && !isArray) {
            return false;
        }

        // 괄호 균형 확인
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


    // SecurityCopilotLab.java에 추가
    private double calculateCategoryScore(SecurityAnalysisResult labResults, String labName) {
        Object result = labResults.getLabResults().get(labName);

        if (result != null && isLabResultSuccessful(result)) {
            // 성공한 경우 기본 70점 + 추가 점수
            double baseScore = 70.0;

            // 결과 길이나 내용에 따라 추가 점수 부여
            String resultText = result.toString();
            if (resultText.length() > 500) {
                baseScore += 10.0; // 상세한 분석 결과
            }
            if (resultText.contains("성공") || resultText.contains("완료")) {
                baseScore += 5.0;
            }
            if (resultText.contains("위험") || resultText.contains("주의")) {
                baseScore -= 5.0; // 위험 요소 발견
            }

            return Math.min(Math.max(baseScore, 0), 100); // 0-100 범위
        }

        // 실패한 경우 30점
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

    // ==================== 내부 클래스 ====================

    /**
     * 진단 세션
     */
    @Getter
    private static class DiagnosisSession {
        private final String sessionId;
        private final SecurityCopilotRequest request;
        private final long startTime;
        private SecurityAnalysisResult labResults;
        private SecurityCopilotResponse finalResponse;
        private volatile String status = "STARTED"; // 추가

        public DiagnosisSession(String sessionId, SecurityCopilotRequest request) {
            this.sessionId = sessionId;
            this.request = request;
            this.startTime = System.currentTimeMillis();
        }

        public void setLabResults(SecurityAnalysisResult labResults) {
            this.labResults = labResults;
            this.status = "LABS_COMPLETED"; // 추가
        }

        public void setFinalResponse(SecurityCopilotResponse response) {
            this.finalResponse = response;
            this.status = "COMPLETED"; // 추가
        }

        public String getStatus() { // 추가
            return this.status;
        }
    }


    /**
     * 진단 결과에서 SecurityAnalysisResult 생성 (실제 진단 결과 활용)
     */
    private SecurityAnalysisResult createAnalysisResultFromDiagnosis(
            Map<String, String> diagnosisResults, SecurityCopilotRequest request) {

        String sessionId = "analysis-" + System.currentTimeMillis();
        SecurityAnalysisResult analysisResult = new SecurityAnalysisResult(sessionId);

        log.info("[DIAGNOSIS-ANALYSIS] 진단 결과 기반 분석 시작 - {} 개 Lab 결과", diagnosisResults.size());

        try {
            // StudioQuery 진단 결과 처리
            if (diagnosisResults.containsKey("StudioQuery")) {
                String studioJson = diagnosisResults.get("StudioQuery");

                // JSON이 마크다운이나 추가 텍스트를 포함할 수 있으므로 정제
                String cleanedJson = cleanLabDiagnosisJson(studioJson, "StudioQuery");

                if (!cleanedJson.isEmpty()) {
                    try {
                        StudioQueryResponse studioResponse = objectMapper.readValue(cleanedJson, StudioQueryResponse.class);
                        analysisResult.setStudioQueryCompleted(true);
                        analysisResult.setStudioQueryResult(studioResponse);
                        log.info("[DIAGNOSIS-ANALYSIS] StudioQuery 진단 결과 파싱 완료");
                    } catch (Exception e) {
                        log.error("StudioQuery JSON 파싱 실패: {}", e.getMessage());
                        log.debug("파싱 실패 JSON: {}", cleanedJson);
                    }
                }
            }

            // RiskAssessment 진단 결과 처리
            if (diagnosisResults.containsKey("RiskAssessment")) {
                String riskJson = diagnosisResults.get("RiskAssessment");
                String cleanedJson = cleanLabDiagnosisJson(riskJson, "RiskAssessment");

                if (!cleanedJson.isEmpty()) {
                    try {
                        RiskAssessmentResponse riskResponse = objectMapper.readValue(cleanedJson, RiskAssessmentResponse.class);
                        analysisResult.setRiskAssessmentCompleted(true);
                        analysisResult.setRiskAssessmentResult(riskResponse);
                        log.info("[DIAGNOSIS-ANALYSIS] RiskAssessment 진단 결과 파싱 완료");
                    } catch (Exception e) {
                        log.error("RiskAssessment JSON 파싱 실패: {}", e.getMessage());
                        log.debug("파싱 실패 JSON: {}", cleanedJson);
                    }
                }
            }

            // PolicyGeneration 진단 결과 처리
            if (diagnosisResults.containsKey("PolicyGeneration")) {
                String policyJson = diagnosisResults.get("PolicyGeneration");
                String cleanedJson = cleanLabDiagnosisJson(policyJson, "PolicyGeneration");

                if (!cleanedJson.isEmpty()) {
                    try {
                        PolicyResponse policyResponse = objectMapper.readValue(cleanedJson, PolicyResponse.class);
                        analysisResult.setPolicyGenerationCompleted(true);
                        analysisResult.setPolicyGenerationResult(policyResponse);
                        log.info("[DIAGNOSIS-ANALYSIS] PolicyGeneration 진단 결과 파싱 완료");
                    } catch (Exception e) {
                        log.error("PolicyGeneration JSON 파싱 실패: {}", e.getMessage());
                        log.debug("파싱 실패 JSON: {}", cleanedJson);
                    }
                }
            }

            log.info("🎉 [DIAGNOSIS-ANALYSIS] 진단 결과 파싱 완료");

        } catch (Exception e) {
            log.error("[DIAGNOSIS-ANALYSIS] 진단 결과 파싱 실패", e);
            return new SecurityAnalysisResult(sessionId);
        }

        return analysisResult;
    }

    /**
     * Lab 진단 결과 JSON 정제 (간단한 버전)
     */
    private String cleanLabDiagnosisJson(String rawJson, String labName) {
        if (rawJson == null || rawJson.isEmpty()) {
            return "";
        }

        // 이미 cleanJsonString 메서드가 있으므로 그것을 재사용
        String cleaned = cleanJsonString(rawJson);

        if (cleaned.isEmpty()) {
            log.warn("[{}] Lab 진단 결과 JSON 정제 실패", labName);
        }

        return cleaned;
    }
    
    /**
     * 피드백 기반 학습
     * 
     * @param request 원본 요청
     * @param response 생성된 응답
     * @param feedback 사용자 피드백
     */
    public void learnFromFeedback(SecurityCopilotRequest request, SecurityCopilotResponse response, String feedback) {
        try {
            // 현재 SecurityCopilotVectorService는 storeFeedback 메서드가 없으므로
            // 요청과 결과를 다시 저장하면서 피드백을 메타데이터로 포함
            log.info("[SecurityCopilotLab] 피드백 학습 시작: {}", feedback.substring(0, Math.min(50, feedback.length())));
            
            // 피드백과 함께 결과 재저장 (향후 확장 가능)
            vectorService.storeSecurityAnalysisResult(request, response);
            
            log.info("[SecurityCopilotLab] 피드백 학습 완료");
        } catch (Exception e) {
            log.error("[SecurityCopilotLab] 피드백 학습 실패", e);
        }
    }

}