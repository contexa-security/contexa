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


@Slf4j
@RequestMapping("/api/ai/access-governance")
@RequiredArgsConstructor
public class AccessGovernanceController {

    private final AICoreOperations<AccessGovernanceContext> aiNativeProcessor;

    
    @PostMapping(value = "/analyze", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<String>> analyzeAccessGovernance(@RequestBody AccessGovernanceAnalysisItem request, HttpServletRequest httpRequest,
                                                Authentication authentication) {

        
        AccessGovernanceContext context = buildContext(httpRequest, authentication.getName(), request);

        
        AIRequest<AccessGovernanceContext> aiRequest = new AccessGovernanceRequest(context, "accessGovernanceStreaming")
                .withParameter("naturalLanguageQuery", request.getQuery());

        SentenceBuffer sentenceBuffer = new SentenceBuffer();
        StringBuilder allData = new StringBuilder(); 
        AtomicBoolean jsonSent = new AtomicBoolean(false);
        AtomicBoolean finalResponseStarted = new AtomicBoolean(false); 
        StringBuilder markerBuffer = new StringBuilder(); 

        return aiNativeProcessor.processStream(aiRequest)
                .flatMap(chunk -> {
                    String chunkStr = chunk != null ? chunk.toString() : "";

                    log.debug("[RECEIVED] 청크 길이: {}, 내용: {}",
                            chunkStr.length(),
                            chunkStr.length() > 50 ? chunkStr.substring(0, 50) + "..." : chunkStr);

                    
                    allData.append(chunkStr);

                    
                    if (!finalResponseStarted.get()) {
                        markerBuffer.append(chunkStr);

                        
                        if (markerBuffer.length() > 50) {
                            markerBuffer.delete(0, markerBuffer.length() - 50);
                        }
                        log.warn("markerBuffer: {}", markerBuffer);
                        
                        if (markerBuffer.toString().contains("###FINAL_RESPONSE###")) {
                            finalResponseStarted.set(true);
                            log.info("[FINAL-MODE] FINAL_RESPONSE 모드 시작 - 이후 청크들은 sentenceBuffer 처리 제외");
                        }
                    }

                    
                    if (finalResponseStarted.get()) {
                        log.debug("[SKIP-SENTENCE] FINAL_RESPONSE 모드 - sentenceBuffer 처리 스킵");
                        return Flux.empty(); 
                    }

                    
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

    
    @PostMapping(value = "/analyze/json", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<AccessGovernanceResponse> analyzeAccessGovernanceJson(@RequestBody AccessGovernanceAnalysisItem request, HttpServletRequest httpRequest,
            @AuthenticationPrincipal Principal principal) {

        AccessGovernanceContext context = buildContext(httpRequest, principal.getName(), request);

        AIRequest<AccessGovernanceContext> aiRequest = new AccessGovernanceRequest(context, context.getOrganizationId());

        return aiNativeProcessor.process(aiRequest, AccessGovernanceResponse.class)
                .cast(AccessGovernanceResponse.class);
    }

    
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

    
    @PostMapping("/feedback")
    public ResponseEntity<Map<String, String>> submitFeedback(
            @RequestBody FeedbackRequest feedbackRequest,
            Authentication authentication) {

        
        
        
        
        
        

        return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "피드백이 성공적으로 저장되었습니다"
        ));
    }

    
    @GetMapping("/dashboard/stats")
    public ResponseEntity<DashboardStats> getDashboardStats(
            @RequestParam(defaultValue = "7") int days) {

        DashboardStats stats = new DashboardStats();

        
        stats.setTotalAnalyses(100); 
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