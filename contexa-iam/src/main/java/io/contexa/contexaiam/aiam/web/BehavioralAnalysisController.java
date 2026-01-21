package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.std.labs.behavior.BehavioralAnalysisLab;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacommon.domain.BehavioralAnalysisItem;
import io.contexa.contexacommon.domain.context.BehavioralAnalysisContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.service.BehaviorProfileService;
import io.contexa.contexaiam.aiam.service.RealTimeBehaviorMonitor;
import io.contexa.contexaiam.aiam.utils.SentenceBuffer;
import io.contexa.contexacommon.domain.request.BehavioralAnalysisRequest;
import io.contexa.contexacommon.domain.response.BehavioralAnalysisResponse;
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
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;


@Slf4j
@RequestMapping("/api/ai/behavior-analysis")
@RequiredArgsConstructor
public class BehavioralAnalysisController {

    private final AICoreOperations<BehavioralAnalysisContext> aiNativeProcessor;
    private final BehavioralAnalysisLab behavioralAnalysisLab;
    private final BehaviorProfileService profileService;
    private final RealTimeBehaviorMonitor realtimeMonitor;


    @PostMapping(value = "/analyze", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<String>> analyzeUserBehavior(@RequestBody BehavioralAnalysisItem request, HttpServletRequest httpRequest,
                                                             @AuthenticationPrincipal Principal principal) {


        BehavioralAnalysisContext context = buildContext(httpRequest, principal.getName());


        AIRequest<BehavioralAnalysisContext> aiRequest = BehavioralAnalysisRequest
                .create(context, "behavioralAnalysisStreaming")
                .withParameter("naturalLanguageQuery", request.getQuery());


        realtimeMonitor.startMonitoring(context.getUserId());

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
                    log.error("AI Studio 스트리밍 처리 중 오류", error);


                    String errorMessage;
                    if (error instanceof Throwable) {
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
    public Mono<BehavioralAnalysisResponse> analyzeUserBehaviorJson(@RequestBody BehavioralAnalysisItem request, HttpServletRequest httpRequest,
                                                                    @AuthenticationPrincipal Principal principal) {

        BehavioralAnalysisContext context = buildContext(httpRequest, principal.getName());

        AIRequest<BehavioralAnalysisContext> aiRequest = BehavioralAnalysisRequest.create(context, context.getOrganizationId());

        return aiNativeProcessor.process(aiRequest, BehavioralAnalysisResponse.class)
                .cast(BehavioralAnalysisResponse.class);
    }


    @GetMapping(value = "/monitor/realtime", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<String> monitorRealtimeBehaviors(Authentication authentication) {

        if (!hasAdminRole(authentication)) {
            return Flux.error(new SecurityException("관리자 권한이 필요합니다"));
        }

        return realtimeMonitor.streamAllUserBehaviors()
                .map(this::formatMonitoringData);
    }


    @GetMapping("/profile/{userId}")
    public ResponseEntity<Map<String, Object>> getUserBehaviorProfile(
            @PathVariable String userId,
            @RequestParam(defaultValue = "30") int days) {

        Map<String, Object> profile = profileService.getUserProfile(userId, days);
        return ResponseEntity.ok(profile);
    }


    @PostMapping("/feedback")
    public ResponseEntity<Map<String, String>> submitFeedback(
            @RequestBody FeedbackRequest feedbackRequest,
            Authentication authentication) {


        behavioralAnalysisLab.learnFromFeedback(
                feedbackRequest.getAnalysisId(),
                feedbackRequest.isCorrect(),
                feedbackRequest.getFeedback()
        );


        profileService.saveFeedback(
                feedbackRequest.getAnalysisId(),
                feedbackRequest.isCorrect(),
                feedbackRequest.getFeedback(),
                authentication.getName()
        );

        return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "피드백이 성공적으로 저장되었습니다"
        ));
    }


    @GetMapping("/dashboard/stats")
    public ResponseEntity<DashboardStats> getDashboardStats(
            @RequestParam(defaultValue = "7") int days) {

        DashboardStats stats = new DashboardStats();


        stats.setTotalUsers(profileService.getTotalUserCount());


        stats.setActiveUsersToday(profileService.getActiveUserCount(LocalDateTime.now()));


        stats.setAnomaliesDetected(profileService.getAnomalyCount(days));


        stats.setRiskDistribution(profileService.getRiskLevelDistribution(days));


        stats.setHourlyAnomalyTrend(profileService.getHourlyAnomalyTrend(days));


        stats.setRecentHighRiskEvents(profileService.getRecentHighRiskEvents(10));

        return ResponseEntity.ok(stats);
    }


    @GetMapping("/anomalies/{userId}")
    public ResponseEntity<List<AnomalyEvent>> getUserAnomalies(
            @PathVariable String userId,
            @RequestParam(defaultValue = "30") int days,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        List<AnomalyEvent> anomalies = profileService.getUserAnomalies(userId, days, page, size);
        return ResponseEntity.ok(anomalies);
    }


    @PostMapping("/dynamic-permissions")
    public ResponseEntity<Map<String, String>> setDynamicPermission(
            @RequestBody DynamicPermissionRequest request,
            Authentication authentication) {


        if (!hasAdminRole(authentication)) {
            return ResponseEntity.status(403).body(Map.of(
                    "error", "관리자 권한이 필요합니다"
            ));
        }

        profileService.createDynamicPermission(
                request.getConditionExpression(),
                request.getApplicableTo(),
                request.getPermissionAdjustment(),
                request.getDescription(),
                authentication.getName()
        );

        return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "동적 권한 규칙이 생성되었습니다"
        ));
    }


    @PostMapping("/batch-learning/trigger")
    public ResponseEntity<Map<String, String>> triggerBatchLearning(
            Authentication authentication) {


        if (!hasAdminRole(authentication)) {
            return ResponseEntity.status(403).body(Map.of(
                    "error", "관리자 권한이 필요합니다"
            ));
        }


        behavioralAnalysisLab.performBatchLearning()
                .thenAccept(v -> log.info("배치 학습 완료"))
                .exceptionally(e -> {
                    log.error("배치 학습 실패", e);
                    return null;
                });

        return ResponseEntity.ok(Map.of(
                "status", "started",
                "message", "배치 학습이 시작되었습니다"
        ));
    }



    private BehavioralAnalysisContext buildContext(
            HttpServletRequest httpRequest,
            String username) {

        BehavioralAnalysisContext context = new BehavioralAnalysisContext();

        context.setUserId(username);
        context.setOrganizationId("org");
        context.setCurrentActivity(buildActivityDescription(httpRequest));
        context.setRemoteIp(extractClientIp(httpRequest));

        return context;
    }

    private String buildActivityDescription(HttpServletRequest request) {
        return String.format("%s %s", request.getMethod(), request.getRequestURI());
    }

    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    private String extractOrganizationId(Authentication authentication) {

        return "default-org";
    }

    private boolean hasAdminRole(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
    }

    private String formatMonitoringData(String data) {
        return String.format("data: %s\n\n", data);
    }



    @Data
    public static class FeedbackRequest {
        private String analysisId;
        private boolean correct;
        private String feedback;
    }

    @Data
    public static class DynamicPermissionRequest {
        private String conditionExpression;
        private String applicableTo;
        private String permissionAdjustment;
        private String description;
    }

    @Data
    public static class DashboardStats {
        private long totalUsers;
        private long activeUsersToday;
        private long anomaliesDetected;
        private Map<String, Long> riskDistribution;
        private List<HourlyTrend> hourlyAnomalyTrend;
        private List<HighRiskEvent> recentHighRiskEvents;
    }

    @Data
    public static class AnomalyEvent {
        private String id;
        private String userId;
        private LocalDateTime timestamp;
        private String activity;
        private double riskScore;
        private String riskLevel;
        private List<String> anomalyFactors;
        private String aiSummary;
    }

    @Data
    public static class HourlyTrend {
        private int hour;
        private long count;
        private double avgRiskScore;
    }

    @Data
    public static class HighRiskEvent {
        private String userId;
        private LocalDateTime timestamp;
        private String activity;
        private double riskScore;
        private String summary;
    }
}