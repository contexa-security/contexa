package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.protocol.context.SecurityCopilotContext;
import io.contexa.contexaiam.aiam.protocol.request.SecurityCopilotItem;
import io.contexa.contexaiam.aiam.service.SecurityCopilotMessageProvider;
import io.contexa.contexaiam.aiam.service.SecurityCopilotValidationService;
import io.contexa.contexaiam.aiam.utils.SentenceBuffer;
import io.contexa.contexacommon.domain.request.IAMRequest;
import io.contexa.contexacommon.enums.DiagnosisType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;


@RequiredArgsConstructor
@Slf4j
public class SecurityCopilotController {

    private final AICoreOperations<SecurityCopilotContext> aiNativeProcessor;
    private final SecurityCopilotValidationService validationService;
    private final SecurityCopilotMessageProvider messageProvider;

    
    @GetMapping("/admin/security-copilot")
    public String securityCopilot(Model model) {
        model.addAttribute("activePage", "security-copilot");
        return "admin/security-copilot";
    }

    @GetMapping("/admin/behavior-analysis")
    public String behavioralAnalysis(Model model) {
        model.addAttribute("activePage", "behavior-alAnalysis");
        return "admin/behavior-analysis";
    }

    @GetMapping("/admin/access-governance")
    public String accessGovernance(Model model) {
        model.addAttribute("activePage", "access-governance");
        return "admin/access-governance";
    }
    
    @GetMapping("/api/security-copilot/labs")
    @ResponseBody
    public ResponseEntity<List<Map<String, Object>>> getAvailableLabs() {
        log.info("사용 가능한 Lab 정보 조회 요청");

        try {
            
            List<Map<String, Object>> labs = java.util.Arrays.asList(
                    createLabInfo("StudioQuery", "Studio Query Lab", "사용자 권한 및 역할 분석", "fas fa-search", "#3b82f6"),
                    createLabInfo("RiskAssessment", "Risk Assessment Lab", "보안 위험 평가 및 분석", "fas fa-shield-alt", "#ef4444"),
                    createLabInfo("PolicyGeneration", "Policy Generation Lab", "정책 생성 및 최적화", "fas fa-file-contract", "#10b981")
            );

            log.info("{} 개의 Lab 정보 반환", labs.size());
            return ResponseEntity.ok(labs);

        } catch (Exception e) {
            log.error("Lab 정보 조회 실패", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    
    private Map<String, Object> createLabInfo(String id, String name, String description, String icon, String color) {
        Map<String, Object> lab = new java.util.HashMap<>();
        lab.put("id", id);
        lab.put("name", name);
        lab.put("description", description);
        lab.put("icon", icon);
        lab.put("color", color);

        
        List<String> patterns = java.util.Arrays.asList(
                id + " Lab 분석이 완료되었습니다",
                id + " Lab 분석 완료",
                id + " 분석이 완료"
        );
        lab.put("patterns", patterns);

        return lab;
    }

    
    @PostMapping(value = "/api/security-copilot/analyze", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @ResponseBody
    public Flux<ServerSentEvent<String>> analyzeUnified(@RequestBody SecurityCopilotItem request) {
        
        String validationError = validationService.validateStreamingRequest(request);
        if (validationError != null) {
            log.warn("[일원화] Security Copilot 요청 검증 실패: {}", validationError);
            return Flux.just(ServerSentEvent.<String>builder()
                    .event("error")
                    .data("ERROR: " + validationError)
                    .build());
        }

        log.info("[일원화] {}", messageProvider.getStreamingStartMessage());
        log.info("[일원화] {}", messageProvider.getAnalysisStartMessage(request.getSecurityQuery()));

        AIRequest<SecurityCopilotContext> aiRequest = createStreamingAIRequest(request);
        SentenceBuffer sentenceBuffer = new SentenceBuffer();
        StringBuilder allData = new StringBuilder(); 
        AtomicBoolean jsonSent = new AtomicBoolean(false);
        AtomicBoolean finalResponseStarted = new AtomicBoolean(false); 
        StringBuilder markerBuffer = new StringBuilder(); 

        
        return aiNativeProcessor.processStream(aiRequest)
                .flatMap(chunk -> {
                    String chunkStr = chunk != null ? chunk.toString() : "";





                    
                    allData.append(chunkStr);

                    
                    if (!finalResponseStarted.get()) {
                        markerBuffer.append(chunkStr);

                        
                        if (markerBuffer.length() > 50) {
                            markerBuffer.delete(0, markerBuffer.length() - 50);
                        }

                        
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
                .doOnComplete(() -> {
                    log.info("[일원화] {}", messageProvider.getStreamingCompleteMessage());
                })
                .onErrorResume(error -> {
                    
                    Throwable throwable = (Throwable) error;
                    String errorMessage = messageProvider.createSafeErrorMessage("일원화 스트리밍", throwable);
                    log.error("[일원화] {}", errorMessage);

                    return Flux.just(ServerSentEvent.<String>builder()
                            .event("error")
                            .data("ERROR: " + messageProvider.getStreamingErrorMessage(throwable.getMessage()))
                            .build());
                });
    }
    
    private AIRequest<SecurityCopilotContext> createStreamingAIRequest(SecurityCopilotItem request) {
        SecurityCopilotContext context = new SecurityCopilotContext(
                request.getUserId(),
                "session-" + System.currentTimeMillis()
        );

        context.setSecurityQuery(request.getSecurityQuery());
        context.setAnalysisScope(request.getAnalysisScope() != null ? request.getAnalysisScope() : "COMPREHENSIVE");
        context.setOrganizationId(request.getOrganizationId());

        
        String orgId = request.getOrganizationId();
        if (orgId == null || orgId.trim().isEmpty()) {
            orgId = "default-org";
        }

        return (IAMRequest<SecurityCopilotContext>) new IAMRequest<>(context, "securityCopilotStream")
                .withDiagnosisType(DiagnosisType.SECURITY_COPILOT)
                .withParameter("processingMode", "streaming")
                .withParameter("securityQuery", request.getSecurityQuery())
                .withParameter("naturalLanguageQuery", request.getSecurityQuery())
                .withParameter("analysisScope", request.getAnalysisScope())
                .withParameter("priority", request.getPriority())
                .withParameter("userId", request.getUserId())
                .withParameter("organizationId", orgId)
                .withStreaming(true);
    }

    
    private String extractSessionId(String chunk) {
        if (chunk.contains("SESSION_ID:")) {
            return chunk.substring(chunk.indexOf("SESSION_ID:") + 11).trim();
        }
        return null;
    }
}