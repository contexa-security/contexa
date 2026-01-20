package io.contexa.contexaiam.aiam.service;

import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SessionState;
import io.contexa.contexacoreenterprise.soar.service.SoarToolCallingService;
import io.contexa.contexaiam.aiam.web.SoarSimulationController.SimulationStartRequest;
import io.contexa.contexaiam.aiam.web.SoarSimulationController.SimulationEvent;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;


@Slf4j
public class SoarSimulationService {
    
    private final SoarToolCallingService soarToolCallingService;
    private final SimpMessagingTemplate brokerTemplate;


    
    
    private final Map<String, SimulationSession> activeSessions = new ConcurrentHashMap<>();

    public SoarSimulationService(SoarToolCallingService soarToolCallingService,
                                 @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        this.soarToolCallingService = soarToolCallingService;
        this.brokerTemplate = brokerTemplate;
    }

    
    public Mono<SimulationResult> startSimulation(SimulationStartRequest request) {
        log.info("SOAR 시뮬레이션 시작: incidentId={}", 
            request.getIncidentId() != null ? request.getIncidentId() : "null (자동 생성 예정)");
        
        
        SoarContext soarContext = createSoarContext(request);
        
        
        String sessionId = UUID.randomUUID().toString();
        String conversationId = UUID.randomUUID().toString();
        
        
        SimulationSession session = SimulationSession.builder()
            .sessionId(sessionId)
            .conversationId(conversationId)
            .incidentId(request.getIncidentId())
            .soarContext(soarContext)
            .status("INITIALIZING")
            .currentStage("PREPROCESSING")
            .progress(0)
            .executedTools(new ArrayList<>())
            .pendingApprovals(new ArrayList<>())
            .startTime(LocalDateTime.now())
            .build();
        
        activeSessions.put(sessionId, session);
        
        
        notifySimulationStarted(sessionId, request);
        
        
        startPipelineTracking(sessionId);
        
        
        return soarToolCallingService.executeWithApproval(
                request.getUserQuery() != null ? request.getUserQuery() : buildDefaultQuery(request),
                request.getIncidentId(),
                request.getOrganizationId(),
                soarContext
            )
            .map(executionResult -> {
                
                session.setStatus("COMPLETED");
                session.setProgress(100);
                session.setEndTime(LocalDateTime.now());
                
                
                notifySimulationComplete(sessionId, executionResult);
                
                return SimulationResult.builder()
                    .sessionId(sessionId)
                    .conversationId(executionResult.getConversationId())
                    .success(executionResult.isSuccess())
                    .finalResponse(executionResult.getFinalResponse())
                    .executedTools(executionResult.getExecutedTools())
                    .durationMs(executionResult.getDurationMs())
                    .build();
            })
            .subscribeOn(Schedulers.boundedElastic())
            .doOnError(error -> {
                log.error("SOAR 시뮬레이션 실패: sessionId={}", sessionId, error);
                session.setStatus("FAILED");
                session.setError(error.getMessage());
                notifySimulationError(sessionId, error);
            })
            .doFinally(signal -> {
                
                if (!"COMPLETED".equals(session.getStatus()) && !"FAILED".equals(session.getStatus())) {
                    log.warn("비정상 종료 감지, 완료 이벤트 강제 전송: sessionId={}, signal={}", sessionId, signal);
                    session.setStatus("COMPLETED");
                    session.setEndTime(LocalDateTime.now());
                    
                    
                    SoarToolCallingService.SoarExecutionResult fallbackResult = 
                        SoarToolCallingService.SoarExecutionResult.builder()
                            .conversationId(conversationId)
                            .success(false)
                            .finalResponse("분석이 종료되었습니다.")
                            .executedTools(session.getExecutedTools())
                            .durationMs(System.currentTimeMillis() - session.getStartTime().toEpochSecond(java.time.ZoneOffset.UTC) * 1000)
                            .build();
                    
                    notifySimulationComplete(sessionId, fallbackResult);
                }
            });
    }
    
    
    public Optional<SessionStatus> getSessionStatus(String sessionId) {
        SimulationSession session = activeSessions.get(sessionId);
        if (session == null) {
            return Optional.empty();
        }
        
        
        Map<String, Boolean> mcpStatus = getMcpServerStatus();
        
        return Optional.of(SessionStatus.builder()
            .sessionId(sessionId)
            .status(session.getStatus())
            .currentStage(session.getCurrentStage())
            .progress(session.getProgress())
            .executedTools(session.getExecutedTools())
            .pendingApprovals(session.getPendingApprovals())
            .mcpServersStatus(mcpStatus)
            .build());
    }
    
    
    public void handleApproval(String sessionId, String approvalId, boolean approved, String reason) {
        log.info("승인 처리: sessionId={}, approvalId={}, approved={}", 
            sessionId, approvalId, approved);
        
        SimulationSession session = activeSessions.get(sessionId);
        if (session == null) {
            log.warn("세션을 찾을 수 없음: {}", sessionId);
            return;
        }
        
        
        session.getPendingApprovals().remove(approvalId);
        
        
        if (approved) {
            session.getSoarContext().approveTool(approvalId);
        }
        
        
        notifyApprovalProcessed(sessionId, approvalId, approved, reason);
        
        
        resumeWorkflow(sessionId);
    }
    
    
    public Map<String, Boolean> getMcpServerStatus() {
        Map<String, Boolean> status = new HashMap<>();
        
        
        
        status.put("context7", true);    
        status.put("sequential", true);  
        status.put("magic", false);      
        status.put("playwright", false); 
        
        return status;
    }
    
    
    
    private SoarContext createSoarContext(SimulationStartRequest request) {
        SoarContext context = new SoarContext();
        
        
        String incidentId = request.getIncidentId();
        if (incidentId == null || incidentId.trim().isEmpty()) {
            incidentId = "INC-" + UUID.randomUUID().toString();
            log.warn("incidentId가 비어있어 자동 생성: {}", incidentId);
        }
        context.setIncidentId(incidentId);
        context.setThreatType(request.getThreatType());
        context.setDescription(request.getDescription());
        context.setAffectedAssets(request.getAffectedAssets());
        context.setDetectedSource(request.getDetectedSource());
        context.setSeverity(request.getSeverity());
        context.setOrganizationId(request.getOrganizationId());
        context.setSessionState(SessionState.ACTIVE);
        context.setCreatedAt(LocalDateTime.now());
        
        
        context.setThreatLevel(mapSeverityToThreatLevel(request.getSeverity()));
        
        return context;
    }
    
    private SoarContext.ThreatLevel mapSeverityToThreatLevel(String severity) {
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> SoarContext.ThreatLevel.CRITICAL;
            case "HIGH" -> SoarContext.ThreatLevel.HIGH;
            case "MEDIUM" -> SoarContext.ThreatLevel.MEDIUM;
            case "LOW" -> SoarContext.ThreatLevel.LOW;
            default -> SoarContext.ThreatLevel.INFO;
        };
    }
    
    private String buildDefaultQuery(SimulationStartRequest request) {
        return String.format(
            "Analyze security incident: %s. Threat type: %s. Affected assets: %s. Severity: %s",
            request.getDescription(),
            request.getThreatType(),
            String.join(", ", request.getAffectedAssets()),
            request.getSeverity()
        );
    }
    
    private void startPipelineTracking(String sessionId) {
        
        Schedulers.boundedElastic().schedule(() -> {
            SimulationSession session = activeSessions.get(sessionId);
            if (session == null) return;
            
            
            String[] stages = {
                "PREPROCESSING",
                "CONTEXT_RETRIEVAL",
                "PROMPT_GENERATION",
                "LLM_EXECUTION",
                "RESPONSE_PARSING",
                "POSTPROCESSING"
            };
            
            for (int i = 0; i < stages.length; i++) {
                if (!"ACTIVE".equals(session.getStatus()) && 
                    !"INITIALIZING".equals(session.getStatus())) {
                    break;
                }
                
                String stage = stages[i];
                int progress = (i + 1) * 100 / stages.length;
                
                session.setCurrentStage(stage);
                session.setProgress(progress);
                
                
                notifyPipelineProgress(sessionId, stage, progress);
                
                
                try {
                    Thread.sleep(2000); 
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
    }
    
    private void resumeWorkflow(String sessionId) {
        SimulationSession session = activeSessions.get(sessionId);
        if (session == null) return;
        
        log.info("워크플로우 재개: sessionId={}", sessionId);
        session.setStatus("ACTIVE");
        
        
        startPipelineTracking(sessionId);
    }
    
    
    
    private void notifySimulationStarted(String sessionId, SimulationStartRequest request) {
        Map<String, Object> eventData = new HashMap<>();
        eventData.put("incidentId", request.getIncidentId() != null ? request.getIncidentId() : "");
        eventData.put("threatType", request.getThreatType() != null ? request.getThreatType() : "");
        eventData.put("severity", request.getSeverity() != null ? request.getSeverity() : "");
        
        SimulationEvent event = SimulationEvent.builder()
            .sessionId(sessionId)
            .eventType("SIMULATION_STARTED")
            .data(eventData)
            .timestamp(LocalDateTime.now())
            .build();
        
        brokerTemplate.convertAndSend("/topic/soar/events", event);
        log.info("시뮬레이션 시작 알림 전송: sessionId={}", sessionId);
    }
    
    private void notifyPipelineProgress(String sessionId, String stage, int progress) {
        PipelineProgressEvent event = PipelineProgressEvent.builder()
            .sessionId(sessionId)
            .stage(stage)
            .progress(progress)
            .message(getPipelineStageMessage(stage))
            .timestamp(LocalDateTime.now())
            .build();

        brokerTemplate.convertAndSend("/topic/soar/pipeline", event);
    }
    
    private void notifySimulationComplete(String sessionId, SoarToolCallingService.SoarExecutionResult result) {
        SimulationCompleteEvent event = SimulationCompleteEvent.builder()
            .sessionId(sessionId)
            .success(result.isSuccess())
            .finalResponse(result.getFinalResponse())  
            .executedTools(result.getExecutedTools())
            .durationMs(result.getDurationMs())
            .timestamp(LocalDateTime.now())
            .build();

        brokerTemplate.convertAndSend("/topic/soar/complete", event);
        log.info("SOAR 시뮬레이션 완료 알림 전송: sessionId={}, finalResponse length={}", 
            sessionId, result.getFinalResponse() != null ? result.getFinalResponse().length() : 0);
    }
    
    private void notifySimulationError(String sessionId, Throwable error) {
        SimulationErrorEvent event = SimulationErrorEvent.builder()
            .sessionId(sessionId)
            .error(error.getMessage())
            .timestamp(LocalDateTime.now())
            .build();

        brokerTemplate.convertAndSend("/topic/soar/error", event);
    }
    
    private void notifyApprovalProcessed(String sessionId, String approvalId, boolean approved, String reason) {
        ApprovalProcessedEvent event = ApprovalProcessedEvent.builder()
            .sessionId(sessionId)
            .approvalId(approvalId)
            .approved(approved)
            .reason(reason)
            .timestamp(LocalDateTime.now())
            .build();
        
        
        brokerTemplate.convertAndSend("/topic/soar/approval-results/" + approvalId, event);
        
        
        brokerTemplate.convertAndSend("/topic/soar/approvals", event);
    }
    
    private String getPipelineStageMessage(String stage) {
        return switch (stage) {
            case "PREPROCESSING" -> "입력 데이터 전처리 중...";
            case "CONTEXT_RETRIEVAL" -> "보안 컨텍스트 검색 중...";
            case "PROMPT_GENERATION" -> "AI 프롬프트 생성 중...";
            case "LLM_EXECUTION" -> "SOAR 도구 실행 중...";
            case "RESPONSE_PARSING" -> "응답 파싱 중...";
            case "POSTPROCESSING" -> "최종 결과 처리 중...";
            default -> stage;
        };
    }
    
    
    
    @Data
    @Builder
    public static class SimulationSession {
        private String sessionId;
        private String conversationId;
        private String incidentId;
        private SoarContext soarContext;
        private String status;
        private String currentStage;
        private int progress;
        private List<String> executedTools;
        private List<String> pendingApprovals;
        private LocalDateTime startTime;
        private LocalDateTime endTime;
        private String error;
    }
    
    @Data
    @Builder
    public static class SimulationResult {
        private String sessionId;
        private String conversationId;
        private boolean success;
        private String finalResponse;
        private List<String> executedTools;
        private long durationMs;
    }
    
    @Data
    @Builder
    public static class SessionStatus {
        private String sessionId;
        private String status;
        private String currentStage;
        private int progress;
        private List<String> executedTools;
        private List<String> pendingApprovals;
        private Map<String, Boolean> mcpServersStatus;
    }
    
    @Data
    @Builder
    public static class PipelineProgressEvent {
        private String sessionId;
        private String stage;
        private int progress;
        private String message;
        private LocalDateTime timestamp;
    }
    
    @Data
    @Builder
    public static class SimulationCompleteEvent {
        private String sessionId;
        private boolean success;
        private String finalResponse;  
        private List<String> executedTools;
        private long durationMs;
        private LocalDateTime timestamp;
    }
    
    @Data
    @Builder
    public static class SimulationErrorEvent {
        private String sessionId;
        private String error;
        private LocalDateTime timestamp;
    }
    
    @Data
    @Builder
    public static class ApprovalProcessedEvent {
        private String sessionId;
        private String approvalId;
        private boolean approved;
        private String reason;
        private LocalDateTime timestamp;
    }
}