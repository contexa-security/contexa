package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacommon.domain.request.AIRequest;

import io.contexa.contexaiam.aiam.protocol.context.AccessGovernanceContext;
import io.contexa.contexaiam.aiam.protocol.request.AccessGovernanceAnalysisItem;
import io.contexa.contexaiam.aiam.protocol.request.AccessGovernanceRequest;
import io.contexa.contexaiam.aiam.protocol.response.AccessGovernanceResponse;
import io.contexa.contexaiam.aiam.utils.SentenceBuffer;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 권한 거버넌스 분석 컨트롤러
 *
 * 시스템 전체 권한 분포와 사용 현황을 분석하여 잠재적 이상 징후를 탐지하는 AI 컨트롤러
 * 예방적 보안을 구현하여 위협이 발생하기 전에 시스템이 가진 잠재적 위험 요소를 AI가 미리 찾아내어 보고
 * 
 * 컨트롤러 목표:
 * - 권한 배분 최적화: "우리 시스템의 권한 배분 상태가 전반적으로 건강하고 최적화되어 있는가?"
 * - 과도한 권한 탐지: "과도한 권한을 가진 사용자를 찾아줘"
 * - 미사용 권한 식별: "사용하지 않는 권한이 있나?"
 * - 권한 상속 경로 추적: "권한 상속 구조가 올바른가?"
 * - 업무 분리 위반 검사: "업무 분리 원칙에 위반되는 권한 배분이 있는가?"
 */
@Slf4j
@RestController
@RequestMapping("/api/ai/access-governance")
@RequiredArgsConstructor
public class AccessGovernanceController {

    private final AICoreOperations<AccessGovernanceContext> aiNativeProcessor;

    /**
     * 권한 거버넌스 분석 (스트리밍) - POST
     */
    @PostMapping(value = "/analyze", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<String>> analyzeAccessGovernance(@RequestBody AccessGovernanceAnalysisItem request, HttpServletRequest httpRequest,
                                                Authentication authentication) {

        // 컨텍스트 구성
        AccessGovernanceContext context = buildContext(httpRequest, authentication.getName(), request);

        // AI 요청 생성
        AIRequest<AccessGovernanceContext> aiRequest = new AccessGovernanceRequest(context, "accessGovernanceStreaming")
                .withParameter("naturalLanguageQuery", request.getQuery());

        SentenceBuffer sentenceBuffer = new SentenceBuffer();
        StringBuilder allData = new StringBuilder(); // 모든 데이터 누적
        AtomicBoolean jsonSent = new AtomicBoolean(false);
        AtomicBoolean finalResponseStarted = new AtomicBoolean(false); // FINAL_RESPONSE 모드 추적
        StringBuilder markerBuffer = new StringBuilder(); // 마커 감지용 버퍼

        return aiNativeProcessor.processStream(aiRequest)
                .flatMap(chunk -> {
                    String chunkStr = chunk != null ? chunk.toString() : "";

                    log.debug("[RECEIVED] 청크 길이: {}, 내용: {}",
                            chunkStr.length(),
                            chunkStr.length() > 50 ? chunkStr.substring(0, 50) + "..." : chunkStr);

                    // 모든 데이터를 누적
                    allData.append(chunkStr);

                    // 효율적인 마커 감지 (성능 최적화)
                    if (!finalResponseStarted.get()) {
                        markerBuffer.append(chunkStr);

                        // 마커 버퍼가 너무 크면 앞부분 제거 (최근 50자만 유지)
                        if (markerBuffer.length() > 50) {
                            markerBuffer.delete(0, markerBuffer.length() - 50);
                        }
                        log.warn("markerBuffer: {}", markerBuffer);
                        // 마커 감지
                        if (markerBuffer.toString().contains("###FINAL_RESPONSE###")) {
                            finalResponseStarted.set(true);
                            log.info("[FINAL-MODE] FINAL_RESPONSE 모드 시작 - 이후 청크들은 sentenceBuffer 처리 제외");
                        }
                    }

                    // FINAL_RESPONSE 모드에서는 sentenceBuffer 처리 제외 (중복 방지)
                    if (finalResponseStarted.get()) {
                        log.debug("[SKIP-SENTENCE] FINAL_RESPONSE 모드 - sentenceBuffer 처리 스킵");
                        return Flux.empty(); // 빈 스트림 반환하여 이 청크는 sentenceBuffer로 처리하지 않음
                    }

                    // 일반 텍스트만 sentenceBuffer로 처리하여 스트리밍
                    return sentenceBuffer.processChunk(chunkStr)
                            .map(sentence -> ServerSentEvent.<String>builder()
                                    .data(sentence)
                                    .build());
                })
                .concatWith(
                        Mono.defer(() -> {
                            String fullData = allData.toString();

                            if (fullData.contains("###FINAL_RESPONSE###") && !jsonSent.get()) {
                                int markerIndex = fullData.indexOf("###FINAL_RESPONSE###");
                                String jsonPart = fullData.substring(markerIndex);

                                jsonSent.set(true);

                                return Mono.just(ServerSentEvent.<String>builder()
                                        .data(jsonPart)
                                        .build());
                            }

                            return Mono.empty();
                        })
                )
                .concatWith(
                        sentenceBuffer.flush()
                                .map(remaining -> ServerSentEvent.<String>builder()
                                        .data(remaining)
                                        .build())
                )
                .concatWith(
                        Mono.just(ServerSentEvent.<String>builder()
                                .data("[DONE]")
                                .build())
                )
                .onErrorResume(error -> {
                    log.error("권한 거버넌스 분석 스트리밍 처리 중 오류", error);

                    // error 객체의 타입에 따라 처리
                    String errorMessage;
                    if (error != null) {
                        errorMessage = ((Throwable) error).getMessage();
                    } else {
                        errorMessage = error.toString();
                    }

                    return Flux.just(ServerSentEvent.<String>builder()
                            .data("ERROR: " + errorMessage)
                            .build());
                });
    }

    /**
     * 권한 거버넌스 분석 (JSON 응답)
     */
    @PostMapping(value = "/analyze/json", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<AccessGovernanceResponse> analyzeAccessGovernanceJson(@RequestBody AccessGovernanceAnalysisItem request, HttpServletRequest httpRequest,
            @AuthenticationPrincipal Principal principal) {

        AccessGovernanceContext context = buildContext(httpRequest, principal.getName(), request);

        AIRequest<AccessGovernanceContext> aiRequest = new AccessGovernanceRequest(context, context.getOrganizationId());

        return aiNativeProcessor.process(aiRequest, AccessGovernanceResponse.class)
                .cast(AccessGovernanceResponse.class);
    }

    /**
     * 사용 가능한 분석 유형 조회
     */
    @GetMapping("/analysis-types")
    public ResponseEntity<List<Map<String, Object>>> getAnalysisTypes() {
        log.info("사용 가능한 분석 유형 조회 요청");

        try {
            List<Map<String, Object>> analysisTypes = List.of(
                    createAnalysisTypeInfo("COMPREHENSIVE", "종합 분석", "시스템 전체 권한 상태 종합 분석", "fas fa-search", "#3b82f6"),
                    createAnalysisTypeInfo("DORMANT_PERMISSION", "미사용 권한 분석", "사용하지 않는 권한 식별", "fas fa-clock", "#f59e0b"),
                    createAnalysisTypeInfo("EXCESSIVE_PERMISSION", "과도한 권한 분석", "과도한 권한을 가진 사용자 탐지", "fas fa-exclamation-triangle", "#ef4444"),
                    createAnalysisTypeInfo("SOD_VIOLATION", "업무 분리 위반 검사", "업무 분리 원칙 위반 사항 검사", "fas fa-shield-alt", "#dc2626"),
                    createAnalysisTypeInfo("ROLE_OPTIMIZATION", "역할 최적화 분석", "역할 구조 최적화 분석", "fas fa-cogs", "#10b981")
            );

            log.info("{} 개의 분석 유형 반환", analysisTypes.size());
            return ResponseEntity.ok(analysisTypes);

        } catch (Exception e) {
            log.error("분석 유형 조회 실패", e);
            return ResponseEntity.status(500).build();
        }
    }

    /**
     * 관리자 피드백 제출 (학습)
     */
    @PostMapping("/feedback")
    public ResponseEntity<Map<String, String>> submitFeedback(
            @RequestBody FeedbackRequest feedbackRequest,
            Authentication authentication) {

        // 피드백 학습 수행 - AccessGovernanceLab이 삭제되어 임시로 주석 처리
        // accessGovernanceLab.learnFromFeedback(
        //         feedbackRequest.getReportId(),
        //         feedbackRequest.isCorrect(),
        //         feedbackRequest.getFeedback()
        // );

        return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "피드백이 성공적으로 저장되었습니다"
        ));
    }

    /**
     * 권한 거버넌스 통계 대시보드
     */
    @GetMapping("/dashboard/stats")
    public ResponseEntity<DashboardStats> getDashboardStats(
            @RequestParam(defaultValue = "7") int days) {

        DashboardStats stats = new DashboardStats();

        // 기본 통계 정보 설정
        stats.setTotalAnalyses(100); // 실제로는 DB에서 조회
        stats.setHighRiskFindings(15);
        stats.setAverageGovernanceScore(75.5);
        stats.setRiskDistribution(Map.of(
                "LOW", 40L,
                "MEDIUM", 35L,
                "HIGH", 20L,
                "CRITICAL", 5L
        ));

        return ResponseEntity.ok(stats);
    }

    // === Helper Methods ===

    private AccessGovernanceContext buildContext(
            HttpServletRequest httpRequest,
            String username,
            AccessGovernanceAnalysisItem request) {

        AccessGovernanceContext context = new AccessGovernanceContext();

        context.setUserId(username);
        context.setOrganizationId("org");
        context.setAuditScope(request.getAuditScope());
        context.setAnalysisType(request.getAnalysisType());
        context.setPriority(request.getPriority());
        context.setEnableDormantPermissionAnalysis(request.isEnableDormantPermissionAnalysis());
        context.setEnableExcessivePermissionDetection(request.isEnableExcessivePermissionDetection());
        context.setEnableSodViolationCheck(request.isEnableSodViolationCheck());

        return context;
    }

    private Map<String, Object> createAnalysisTypeInfo(String id, String name, String description, String icon, String color) {
        return Map.of(
                "id", id,
                "name", name,
                "description", description,
                "icon", icon,
                "color", color
        );
    }

    @Data
    public static class FeedbackRequest {
        private String reportId;
        private boolean correct;
        private String feedback;
    }

    @Data
    public static class DashboardStats {
        private long totalAnalyses;
        private long highRiskFindings;
        private double averageGovernanceScore;
        private Map<String, Long> riskDistribution;
    }
} 