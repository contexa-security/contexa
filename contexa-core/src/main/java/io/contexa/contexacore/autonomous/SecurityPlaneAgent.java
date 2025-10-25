package io.contexa.contexacore.autonomous;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.audit.SecurityPlaneAuditLogger;
import io.contexa.contexacore.autonomous.domain.*;
import io.contexa.contexacore.autonomous.dto.SecurityIncidentDTO;
import io.contexa.contexacore.autonomous.event.IncidentResolvedEvent;
import io.contexa.contexacore.autonomous.helper.LearningEngineHelper;
import io.contexa.contexacore.autonomous.helper.MemorySystemHelper;
import io.contexa.contexacore.autonomous.helper.PolicyEvolutionHelper;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventProcessingOrchestrator;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.service.ISoarContextProvider;
import io.contexa.contexacore.autonomous.service.ISoarNotifier;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.strategy.DynamicStrategySelector;
import io.contexa.contexacore.autonomous.strategy.MitreAttackEvaluationStrategy;
import io.contexa.contexacore.autonomous.strategy.NistCsfEvaluationStrategy;
import io.contexa.contexacore.autonomous.strategy.ThreatEvaluationStrategy;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarExecutionMode;
import io.contexa.contexacore.domain.SoarRequest;
import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.domain.entity.SoarIncident;
import io.contexa.contexacore.infra.redis.RedisAtomicOperations;
import io.contexa.contexacore.repository.SecurityIncidentRepository;
import io.contexa.contexacore.simulation.event.SimulationProcessingCompleteEvent;
import io.contexa.contexacore.soar.approval.McpApprovalNotificationService;
import io.contexa.contexacore.soar.approval.UnifiedApprovalService;
import io.contexa.contexacore.soar.lab.SoarLab;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Security Plane Agent 메인 클래스
 *
 * 24시간 자율 운영되는 보안 플레인 에이전트의 진입점입니다.
 * State 패턴과 Template Method 패턴을 사용하여 에이전트 상태를 관리합니다.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityPlaneAgent implements CommandLineRunner, ISecurityPlaneAgent {

    private final SecurityMonitoringService securityMonitor;
    private final UnifiedApprovalService approvalService;
    private final McpApprovalNotificationService notificationService;
    private final SoarLab soarLab;
    private final ISoarNotifier soarNotifier;
    private final ISoarContextProvider contextProvider;
    private final SecurityIncidentRepository incidentRepository;
    private final RedisTemplate<String, Object> redisTemplate;
    private final PolicyEvolutionHelper policyEvolutionHelper;
    private final LearningEngineHelper learningEngineHelper;
    private final MemorySystemHelper memorySystemHelper;
    private final ApplicationEventPublisher eventPublisher;
    private final SecurityPlaneAuditLogger auditLogger;
    
    @Value("${security.plane.agent.name:SecurityPlaneAgent-1}")
    private String agentName;

    @Value("${security.plane.agent.auto-start:true}")
    private boolean autoStart;

    @Autowired(required = false)
    private SecurityEventProcessingOrchestrator processingOrchestrator;

    @Value("${security.plane.agent.max-concurrent-incidents:10}")
    private int maxConcurrentIncidents;
    
    @Value("${security.plane.agent.threat-threshold:0.7}")
    private double threatThreshold;
    private AgentState currentState;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong processedEvents = new AtomicLong(0);
    private final AtomicLong createdIncidents = new AtomicLong(0);
    private final AtomicLong executedActions = new AtomicLong(0);
    private final Map<String, IncidentHandler> activeIncidentHandlers = Collections.synchronizedMap(new WeakHashMap<>());
    private ScheduledExecutorService backgroundExecutor;
    private CompletableFuture<Void> backgroundTask;
    
    @PostConstruct
    public void initialize() {
        log.info("Initializing Security Plane Agent: {}", agentName);

        // 감사 추적 시스템 초기화
        if (auditLogger != null) {
            auditLogger.auditAgentStateChange(agentName, "UNINITIALIZED", "INITIALIZING",
                "Security Plane Agent initialization started", null);
        }

        currentState = AgentState.INITIALIZING;
        backgroundExecutor = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, agentName + "-Background");
            t.setDaemon(true);
            return t;
        });

        log.info("Security Plane Agent {} initialized successfully", agentName);
    }
    
    @Override
    public void run(String... args) throws Exception {
        log.info("Starting Security Plane Agent: {}", agentName);
        
        if (autoStart) {
            start();
        } else {
            log.info("Auto-start disabled. Agent {} is in standby mode", agentName);
        }
    }
    
    /**
     * Start the agent
     */
    @Override
    public void start() {
        if (running.compareAndSet(false, true)) {
            log.info("Starting Security Plane Agent {}", agentName);
            currentState = AgentState.RUNNING;
            
            Map<String, Object> config = createMonitoringConfig();
            securityMonitor.startMonitoring(agentName, config);
            
            // Start continuous background monitoring
            startBackgroundMonitoring();
            
            // Schedule periodic cleanup of incident handlers
            backgroundExecutor.scheduleWithFixedDelay(
                this::cleanupIncidentHandlers,
                5, 5, TimeUnit.MINUTES
            );
            
            log.info("Security Plane Agent {} is now running with continuous background monitoring", agentName);
        } else {
            log.warn("Agent {} is already running", agentName);
        }
    }
    
    /**
     * Stop the agent
     */
    @Override
    public void stop() {
        if (running.compareAndSet(true, false)) {
            log.info("Stopping Security Plane Agent {}", agentName);
            currentState = AgentState.STOPPING;
            
            // Stop background monitoring
            stopBackgroundMonitoring();
            
            // Stop monitoring
            securityMonitor.stopMonitoring(agentName);
            
            // Wait for active handlers to complete
            waitForActiveHandlers();
            
            // Shutdown background executor
            if (backgroundExecutor != null) {
                backgroundExecutor.shutdown();
                try {
                    if (!backgroundExecutor.awaitTermination(30, TimeUnit.SECONDS)) {
                        backgroundExecutor.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    backgroundExecutor.shutdownNow();
                    Thread.currentThread().interrupt();
                }
            }
            
            currentState = AgentState.STOPPED;
            log.info("Security Plane Agent {} has stopped", agentName);
        }
    }
    
    @PreDestroy
    public void shutdown() {
        log.info("Shutting down Security Plane Agent {}", agentName);
        stop();
    }
    
    /**
     * Check for new incidents - runs every minute
     */
    @Override
//    @Scheduled(fixedDelayString = "#{${security.plane.agent.incident-check-interval-minutes:1} * 60 * 1000}")
    public void checkForIncidents() {
        if (!isRunning()) {
            return;
        }
        
        try {
            log.debug("Agent {} checking for new incidents", agentName);
            
            // Get active incidents
            List<SecurityIncident> incidents = incidentRepository.findActiveIncidents();
            
            // Process each incident
            for (SecurityIncident incident : incidents) {
                if (!activeIncidentHandlers.containsKey(incident.getIncidentId())) {
                    handleNewIncident(incident);
                }
            }
            
        } catch (Exception e) {
            log.error("Error checking incidents", e);
        }
    }
    
    /**
     * Check pending approvals - runs every 10 seconds
     */
    @Override
//    @Scheduled(fixedDelayString = "#{${security.plane.agent.approval-check-interval-seconds:10} * 1000}")
    public void checkPendingApprovals() {
        if (!isRunning()) {
            return;
        }
        
        try {
            log.debug("Agent {} checking pending approvals", agentName);
            
            // Get pending approval IDs from UnifiedApprovalService
            Set<String> pendingApprovalIds = approvalService.getPendingApprovalIds();
            int pendingCount = approvalService.getPendingCount();
            
            // Log pending approvals for visibility
            if (pendingCount > 0) {
                log.info("Agent {} has {} pending approvals waiting for review",
                    agentName, pendingCount);
                
                // 비동기 모드에서 알림 전송
                for (String approvalId : pendingApprovalIds) {
                    log.info("Pending approval ID: {}", approvalId);
                    
                    // Check approval status
                    ApprovalRequest.ApprovalStatus status = approvalService.getApprovalStatus(approvalId);
                    if (status == ApprovalRequest.ApprovalStatus.PENDING) {
                        // 알림 서비스를 통해 재알림
                        if (notificationService != null) {
                            notificationService.sendApprovalReminder(approvalId);
                        }
                    }
                }
            }
            
        } catch (Exception e) {
            log.error("Error checking approvals", e);
        }
    }
    
    /**
     * Health check - runs every 5 minutes
     */
    @Override
//    @Scheduled(fixedDelayString = "#{${security.plane.agent.health-check-interval-minutes:5} * 60 * 1000}")
    public void performHealthCheck() {
        if (!running.get()) {
            return;
        }
        
        try {
            log.info("Performing health check for agent {}", agentName);
            
            Map<String, Object> health = getHealthStatus();
            log.info("Agent {} health status: {}", agentName, health);
            
            // Check if agent needs attention
            if (needsAttention(health)) {
                log.warn("Agent {} needs attention: {}", agentName, health);
                // In production, this would trigger alerts
            }
            
        } catch (Exception e) {
            log.error("Error in health check", e);
        }
    }
    
    /**
     * 보안 이벤트를 평가하고 대응 실행
     *
     * Clean Code 리팩토링: SecurityEventProcessingOrchestrator를 사용하여
     * 단일 책임 원칙(SRP)과 개방-폐쇄 원칙(OCP)을 준수
     */
    public void processSecurityEvent(SecurityEvent event) {
        log.info("[SecurityPlaneAgent]  is SecurityEventProcessingOrchestrator");
        if (processingOrchestrator != null) {
            processWithOrchestrator(event);
        } else {
            log.error("SecurityEventProcessingOrchestrator is not configured. Cannot process event: {}", event.getEventId());
            throw new IllegalStateException("SecurityEventProcessingOrchestrator must be configured");
        }
    }

    /**
     * 오케스트레이터를 사용한 클린코드 처리
     * 모든 처리 로직이 핸들러 체인으로 위임됨
     *
     * @Transactional 적용으로 DB + Redis 일관성 보장
     */
    @Transactional(rollbackFor = Exception.class)
    public void processWithOrchestrator(SecurityEvent event) {
        long startTime = System.currentTimeMillis();
        SecurityEventContext context = null;

        try {
            // 멱등성 체크 (중복 처리 방지)
            if (isEventAlreadyProcessed(event.getEventId())) {
                log.warn("[SecurityPlaneAgent] Event {} already processed, skipping duplicate",
                    event.getEventId());
                return;
            }

            // 오케스트레이터를 통한 이벤트 처리
            log.info("[SecurityPlaneAgent] Processing event with orchestrator - eventId: {}",
                event.getEventId());
            context = processingOrchestrator.process(event);

            // 처리 시간 측정 및 메트릭 업데이트
            long processingTime = System.currentTimeMillis() - startTime;
            if (context.getProcessingMetrics() == null) {
                context.setProcessingMetrics(new SecurityEventContext.ProcessingMetrics());
            }
            context.getProcessingMetrics().setResponseTimeMs(processingTime);

            // 처리 결과 로깅
            ProcessingMode mode = (ProcessingMode) context.getMetadata().get("processingMode");
            log.info("[SecurityPlaneAgent] Event {} processed in {}ms with mode: {}, status: {}",
                event.getEventId(), processingTime, mode, context.getProcessingStatus());

            // 처리 결과 핸들링 (기존 메서드 재사용)
            ProcessingResult result = (ProcessingResult) context.getMetadata().get("processingResult");
            if (result != null) {
                handleProcessingResult(event, result);
            }

            // 멱등성 마커 저장 (처리 완료 표시)
            markEventAsProcessed(event.getEventId());

            // 성능 메트릭 수집
            recordProcessingMetrics(event.getEventId(), processingTime, "SUCCESS");

        } catch (Exception e) {
            log.error("[SecurityPlaneAgent] Error processing event with orchestrator: {}",
                event.getEventId(), e);

            // 컨텍스트가 없는 경우 생성
            if (context == null) {
                context = SecurityEventContext.builder()
                    .securityEvent(event)
                    .processingStatus(SecurityEventContext.ProcessingStatus.FAILED)
                    .createdAt(LocalDateTime.now())
                    .build();
            }

            context.markAsFailed("Processing error: " + e.getMessage());

            // 에러 감사 기록
            if (auditLogger != null) {
                Map<String, Object> errorContext = Map.of(
                    "eventId", event.getEventId(),
                    "eventType", event.getEventType().toString(),
                    "userId", event.getUserId() != null ? event.getUserId() : "unknown",
                    "processingTime", System.currentTimeMillis() - startTime
                );
                auditLogger.auditError("SecurityPlaneAgent", "processWithOrchestrator", e, errorContext);
            }

            // 성능 메트릭 수집 (실패)
            recordProcessingMetrics(event.getEventId(), System.currentTimeMillis() - startTime, "FAILED");

            // 트랜잭션 롤백을 위해 예외 재발생
            throw new RuntimeException("Event processing failed: " + event.getEventId(), e);

        } finally {
            // 컨텍스트 캐시 저장
            if (context != null) {
                String contextKey = "security:context:" + event.getEventId();
                try {
                    redisTemplate.opsForValue().set(contextKey, context, Duration.ofHours(24));
                } catch (Exception e) {
                    log.warn("[SecurityPlaneAgent] Failed to save context for event: {}", event.getEventId(), e);
                }
            }
        }
    }

    /**
     * 이벤트 처리 여부 확인 (멱등성 체크)
     *
     * @param eventId 이벤트 ID
     * @return 이미 처리된 경우 true
     */
    private boolean isEventAlreadyProcessed(String eventId) {
        try {
            String processingKey = "security:processed:" + eventId;
            Boolean exists = redisTemplate.hasKey(processingKey);
            return Boolean.TRUE.equals(exists);
        } catch (Exception e) {
            log.warn("[SecurityPlaneAgent] Failed to check event processing status: {}", eventId, e);
            return false; // 체크 실패 시 재처리 허용
        }
    }

    /**
     * 이벤트 처리 완료 마킹 (멱등성 보장)
     *
     * @param eventId 이벤트 ID
     */
    private void markEventAsProcessed(String eventId) {
        try {
            String processingKey = "security:processed:" + eventId;
            // 24시간 동안 처리 완료 상태 유지
            redisTemplate.opsForValue().set(processingKey, "1", Duration.ofHours(24));
            log.debug("[SecurityPlaneAgent] Event marked as processed: {}", eventId);
        } catch (Exception e) {
            log.warn("[SecurityPlaneAgent] Failed to mark event as processed: {}", eventId, e);
        }
    }

    /**
     * 처리 성능 메트릭 기록
     *
     * @param eventId 이벤트 ID
     * @param processingTime 처리 시간 (ms)
     * @param status 처리 상태
     */
    private void recordProcessingMetrics(String eventId, long processingTime, String status) {
        try {
            String metricsKey = "security:metrics:processing:" + agentName;
            Map<String, String> metrics = new HashMap<>();
            metrics.put("eventId", eventId);
            metrics.put("processingTime", String.valueOf(processingTime));
            metrics.put("status", status);
            metrics.put("timestamp", String.valueOf(System.currentTimeMillis()));

            // Redis Hash로 메트릭 저장 (최근 1000개 유지)
            redisTemplate.opsForHash().put(metricsKey, eventId, metrics);

            log.debug("[SecurityPlaneAgent] Metrics recorded - eventId: {}, time: {}ms, status: {}",
                eventId, processingTime, status);
        } catch (Exception e) {
            log.warn("[SecurityPlaneAgent] Failed to record processing metrics: {}", eventId, e);
        }
    }

    public void handleNewIncident(SecurityIncident incident) {
        handleNewIncident(incident, null);
    }

    public void handleNewIncident(SecurityIncident incident, SecurityEvent sourceEvent) {
        if (activeIncidentHandlers.size() >= maxConcurrentIncidents) {
            log.warn("Agent {} reached max concurrent incidents limit", agentName);
            return;
        }

        log.info("Agent {} handling new incident: {}", agentName, incident.getIncidentId());

        try {
            // Create incident handler
            IncidentHandler handler = new IncidentHandler(incident.getIncidentId());

            // SoarIncident 생성 및 저장
            SoarIncident soarIncident = new SoarIncident();
            soarIncident.setIncidentId(incident.getIncidentId());
            soarIncident.setType(incident.getType().toString());
            soarIncident.setDescription(incident.getDescription());
            soarIncident.setSeverity(incident.getThreatLevel().toString());
            soarIncident.setStatus(io.contexa.contexacore.domain.SoarIncidentStatus.NEW);
            soarIncident.setCreatedAt(LocalDateTime.now());
            soarIncident.setMetadata(new HashMap<>());
            handler.setSoarIncident(soarIncident);

            // SecurityEvent 저장 (있는 경우)
            if (sourceEvent != null) {
                handler.setSecurityEvent(sourceEvent);
            }

            activeIncidentHandlers.put(incident.getIncidentId(), handler);
            
            // 인시던트에서 학습 (LearningEngineHelper)
            if (learningEngineHelper != null && incident.getAffectedUser() != null) {
                SecurityEvent relatedEvent = new SecurityEvent();
                relatedEvent.setUserId(incident.getAffectedUser());
                relatedEvent.setEventType(SecurityEvent.EventType.INCIDENT_CREATED);
                relatedEvent.setEventId(incident.getIncidentId());
                relatedEvent.setSeverity(mapThreatLevelToSeverity(incident.getThreatLevel()));

                String response = "INCIDENT_" + incident.getType();
                double effectiveness = incident.getRiskScore();

                // 실제 학습 호출 추가 (기존에는 로그만 남김)
                try {
                    learningEngineHelper.learnFromEvent(relatedEvent, response, effectiveness).subscribe(
                        result -> log.debug("[SecurityPlaneAgent] Learning from incident {} - status: {}, processed: {}",
                            incident.getIncidentId(), result.getStatus(), result.getProcessedCount()),
                        error -> log.error("[SecurityPlaneAgent] Failed to learn from incident {}: {}",
                            incident.getIncidentId(), error.getMessage(), error)
                    );
                } catch (Exception e) {
                    // 학습 실패가 메인 흐름을 중단하면 안 됨
                    log.error("[SecurityPlaneAgent] Failed to learn from incident {}: {}",
                        incident.getIncidentId(), e.getMessage(), e);
                }
            }
            
            // 메모리에 인시던트 저장 (MemorySystemHelper)
            if (memorySystemHelper != null) {
                String key = "incident:" + incident.getIncidentId();
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("type", incident.getType());
                metadata.put("threatLevel", incident.getThreatLevel());
                metadata.put("riskScore", incident.getRiskScore());
                storeInMemory(key, incident);
            }
            
            // Create SOAR context from incident - ONLY FOR HIGH RISK INCIDENTS
            if (contextProvider != null && soarNotifier != null) {
                // Check if incident is high risk (CRITICAL or HIGH threat level)
                if (incident.getThreatLevel() != null &&
                    (incident.getThreatLevel() == SecurityIncident.ThreatLevel.CRITICAL ||
                     incident.getThreatLevel() == SecurityIncident.ThreatLevel.HIGH ||
                     (incident.getRiskScore() != null && incident.getRiskScore() >= threatThreshold))) {

                    log.info("High risk incident detected ({}), notifying SOAR - ThreatLevel: {}, RiskScore: {}",
                            incident.getIncidentId(), incident.getThreatLevel(), incident.getRiskScore());

                    SoarContext context = contextProvider.createContextFromIncident(incident);

                    // Notify SOAR about the HIGH RISK incident
                    CompletableFuture<NotificationResult> notificationResult =
                        soarNotifier.notifyIncident(incident, context);

                    notificationResult.thenAccept(result -> {
                        if (result.isSuccess()) {
                            log.info("SOAR notified successfully for high risk incident {}, request ID: {}",
                                incident.getIncidentId(), result.getRequestId());
                            handler.setSoarRequestId(result.getRequestId());
                        } else {
                            log.error("Failed to notify SOAR for high risk incident {}: {}",
                                incident.getIncidentId(), result.getMessage());
                        }
                    });
                } else {
                    log.debug("Incident {} is not high risk (ThreatLevel: {}, RiskScore: {}), skipping SOAR notification",
                            incident.getIncidentId(), incident.getThreatLevel(), incident.getRiskScore());
                }
            } else {
                log.warn("SOAR integration not available for incident {}", incident.getIncidentId());
            }
            
            // Update incident count
            createdIncidents.incrementAndGet();
            
        } catch (Exception e) {
            log.error("Error handling incident {}", incident.getIncidentId(), e);
        }
    }

    /**
     * 인시던트 해결 메소드 - IncidentResolvedEvent 발행
     */
    public void resolveIncident(String incidentId, String resolvedBy, String resolutionMethod, boolean wasSuccessful) {
        IncidentHandler handler = activeIncidentHandlers.get(incidentId);
        if (handler == null) {
            log.warn("Cannot resolve incident - handler not found: {}", incidentId);
            return;
        }

        try {
            // 핸들러 상태 업데이트
            handler.resolveIncident(resolvedBy, resolutionMethod);

            // IncidentResolvedEvent 발행
            IncidentResolvedEvent resolvedEvent = new IncidentResolvedEvent(
                this,
                incidentId,
                handler.getSoarIncident(),
                handler.getSecurityEvent(),
                resolvedBy,
                resolutionMethod,
                handler.getResolutionTimeMs(),
                wasSuccessful
            );

            eventPublisher.publishEvent(resolvedEvent);

            log.info("Incident resolved and event published: {} by {} using {} (success: {}, time: {}ms)",
                incidentId, resolvedBy, resolutionMethod, wasSuccessful, handler.getResolutionTimeMs());

            // 핸들러 제거
            activeIncidentHandlers.remove(incidentId);

        } catch (Exception e) {
            log.error("Failed to resolve incident and publish event: {}", incidentId, e);
        }
    }

    protected void executeRecommendedAction(String action, SecurityEvent event, ThreatAssessment assessment) {
        log.debug("Creating SOAR context for recommended action: {}", action);
        
        if (contextProvider == null || soarNotifier == null) {
            log.warn("SOAR integration not available for recommended action: {}", action);
            return;
        }
        
        // Create context with the recommended action
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put("recommendedAction", action);
        additionalInfo.put("eventId", event.getEventId());
        additionalInfo.put("threatLevel", assessment.getThreatLevel());
        additionalInfo.put("riskScore", assessment.getRiskScore());
        
        // Create context from event
        SoarContext context = contextProvider.createContextFromEvents(List.of(event));
        context = contextProvider.enrichContext(context, additionalInfo);
        
        // Critical 상황에서 SOAR Lab 직접 호출 (AI 분석 필요)
        if (assessment.getThreatLevel() == ThreatAssessment.ThreatLevel.CRITICAL) {
            if (soarLab != null) {
                // SoarLab을 통한 AI 기반 분석 및 도구 실행
                log.info("Invoking SOAR Lab for critical threat analysis");
                try {
                    // 비동기 모드로 SOAR Lab 호출 - doProcessAsync 사용!
                    SoarContext finalContext = context;
                    String prompt = String.format(
                        "Critical security event detected: %s with threat level %s and risk score %.2f. Recommended action: %s. Analyze and determine appropriate SOAR tools to execute.",
                        event.getEventId(), assessment.getThreatLevel(), assessment.getRiskScore(), action
                    );
                    
                    // SoarRequest 생성 - ASYNC 모드 명시
                    finalContext.setExecutionMode(SoarExecutionMode.ASYNC);  // context에 비동기 모드 설정
                    SoarRequest soarRequest = SoarRequest.builder()
                        .context(finalContext)
                        .operation("soarAnalysis")
                        .initialQuery(prompt)  // initialQuery 대신 query 사용
                        .sessionId(UUID.randomUUID().toString())
                        .organizationId("security-plane")
                        .build();
                    
                    // processAsync 사용 - 스트림이 아닌 완전 비동기!
                    soarLab.processAsync(soarRequest)
                        .subscribe(
                            soarResponse -> {
                                log.info("SOAR Lab 분석 완료 - Event: {}, Response: {}",
                                    event.getEventId(), soarResponse.getRecommendations());
                                
                                // 실행된 액션 카운트 증가
                                executedActions.incrementAndGet();
                                
                                // 자율 진화형 정책 패브릭 활용
                                evolveThreadEvaluationPolicy(event, assessment);
                                learnFromSecurityEvent(event, action);
                                storeInMemory("assessment:" + assessment.getAssessmentId(), assessment);
                                
                                // 결과 이벤트 발행
                                Map<String, Object> resultData = new HashMap<>();
                                resultData.put("eventId", event.getEventId());
                                resultData.put("action", action);
                                resultData.put("soarResponse", soarResponse);
                                resultData.put("assessmentId", assessment.getAssessmentId());

                                // notifyActionExecuted 메서드가 없으므로 notifyHighRiskTool 사용
                                soarNotifier.notifyHighRiskTool(
                                    action,
                                    resultData,
                                    finalContext
                                );
                            },
                            error -> {
                                log.error("SOAR Lab 분석 실패 - Event: {}", event.getEventId(), error);
                            }
                        );
                    
                } catch (Exception e) {
                    log.error("Error invoking SOAR Lab for critical event", e);
                }
            } else {
                // SOAR Lab이 없으면 notifier를 통해 알림만
                soarNotifier.notifyCriticalSituation(context);
            }
        }
    }

    private Map<String, Object> createMonitoringConfig() {
        Map<String, Object> config = new HashMap<>();
        config.put("agentId", agentName);
        config.put("autoIncidentCreation", true);
        config.put("threatThreshold", threatThreshold);
        config.put("correlationWindow", 10);
        return config;
    }
    
    private void waitForActiveHandlers() {
        int waitCount = 0;
        while (!activeIncidentHandlers.isEmpty() && waitCount < 60) {
            try {
                Thread.sleep(1000);
                waitCount++;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    /**
     * 모니터링 오류 처리 - EmergencyKillSwitch 활용
     */
    private void handleMonitoringError(Exception e) {
        log.error("Monitoring error in agent {}: {}", agentName, e.getMessage(), e);
        
        // 오류 카운터 증가
        if (currentState == AgentState.ERROR) {
            // 이미 ERROR 상태면 종료 고려
            log.error("Agent {} is in ERROR state, considering shutdown", agentName);
            // EmergencyKillSwitch 트리거 고려
        } else {
            // 일시적 오류로 처리
            log.warn("Temporary monitoring error in agent {}, will retry", agentName);
        }
        
        // 오류 발생 시 백오프 전략 적용
        try {
            Thread.sleep(5000); // 5초 대기
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }
    
    private boolean needsAttention(Map<String, Object> health) {
        // Check if any health metrics indicate problems
        Long queueSize = (Long) health.get("event_queue_size");
        if (queueSize != null && queueSize > 1000) {
            return true;
        }

        Integer pendingApprovals = (Integer) health.get("pending_approvals");
        if (pendingApprovals != null && pendingApprovals > 10) {
            return true;
        }
        
        return false;
    }
    
    @Override
    public boolean isRunning() {
        return running.get() && currentState == AgentState.RUNNING;
    }
    
    public Map<String, Object> getHealthStatus() {
        Map<String, Object> health = new HashMap<>();
        health.put("agent_name", agentName);
        health.put("state", currentState.toString());
        health.put("running", running.get());
        health.put("processed_events", processedEvents.get());
        health.put("created_incidents", createdIncidents.get());
        health.put("executed_actions", executedActions.get());
        health.put("active_incident_handlers", activeIncidentHandlers.size());
        
        // Add monitoring statistics
        health.putAll(securityMonitor.getMonitoringStatistics());
        
        // Add pending approvals count from UnifiedApprovalService
        health.put("pending_approvals", approvalService.getPendingCount());
        
        return health;
    }
    

    /**
     * Hot/Cold Path 처리 결과를 받아서 인시던트 처리
     */
    private void handleProcessingResult(SecurityEvent event, ProcessingResult result) {
        if (result == null) {
            log.warn("Processing result is null for event: {}", event.getEventId());
            return;
        }
        
        String userId = event.getUserId();
        if (userId == null) {
            return;
        }
        
        try {

            // 인시던트 생성 (필요시)
            if (result.isRequiresIncident()) {
                createIncidentFromResult(event, result);
            }
            
            // 추천 액션 실행
            if (result.getRecommendedActions() != null && !result.getRecommendedActions().isEmpty()) {
                for (String action : result.getRecommendedActions()) {
                    executeRecommendedAction(action, event, null);
                }
            }
            
            // 4. 처리 성공 로그
            log.info("Processed event {} via {} - threatAdjustment: {}, processingTime: {}ms",
                    event.getEventId(), 
                    result.getProcessingPath(),
                    result.getThreatScoreAdjustment(),
                    result.getProcessingTimeMs());
            
            // 5. 성능 경고 (필요시)
            if (result.getProcessingPath() == ProcessingResult.ProcessingPath.HOT_PATH
                && result.getProcessingTimeMs() > 50) {
                log.warn("Hot Path processing exceeded 50ms target: {}ms for event {}",
                        result.getProcessingTimeMs(), event.getEventId());
            }


        } catch (Exception e) {
            log.error("Failed to handle processing result for event: {}", event.getEventId(), e);
        }
    }
    
    /**
     * ProcessingResult 로부터 인시던트 생성
     */
    private void createIncidentFromResult(SecurityEvent event, ProcessingResult result) {
        try {
            // getIncidentSeverity()가 String을 반환하므로 처리
            String severityStr = result.getIncidentSeverity();
            ProcessingResult.IncidentSeverity severity = severityStr != null ?
                ProcessingResult.IncidentSeverity.valueOf(severityStr) :
                ProcessingResult.IncidentSeverity.MEDIUM;
            SecurityIncident.ThreatLevel threatLevel = mapSeverityToThreatLevel(severity);
            
            SecurityIncident incident = SecurityIncident.builder()
                    .incidentId("INC-" + result.getProcessingPath() + "-" + System.currentTimeMillis())
                    .type(mapEventTypeToIncidentType(event.getEventType()))
                    .threatLevel(threatLevel)
                    .status(SecurityIncident.IncidentStatus.NEW)
                    .description(String.format("%s path detected %s threat",
                            result.getProcessingPath(), severity))
                    .sourceIp(event.getSourceIp())
                    .affectedUser(event.getUserId())
                    .detectedBy(agentName)
                    .detectionSource(result.getProcessingPath().toString())
                    .detectedAt(LocalDateTime.now())
                    .riskScore(result.getCurrentRiskLevel())
                    .autoResponseEnabled(severity == ProcessingResult.IncidentSeverity.CRITICAL)
                    .build();
            
            handleNewIncident(incident, event);

        } catch (Exception e) {
            log.error("Failed to create incident from processing result", e);
        }
    }
    
    /**
     * IncidentSeverity를 ThreatLevel로 매핑
     */
    private SecurityIncident.ThreatLevel mapSeverityToThreatLevel(ProcessingResult.IncidentSeverity severity) {
        if (severity == null) {
            return SecurityIncident.ThreatLevel.MEDIUM;
        }
        
        switch (severity) {
            case CRITICAL:
                return SecurityIncident.ThreatLevel.CRITICAL;
            case HIGH:
                return SecurityIncident.ThreatLevel.HIGH;
            case MEDIUM:
                return SecurityIncident.ThreatLevel.MEDIUM;
            case LOW:
                return SecurityIncident.ThreatLevel.LOW;
            default:
                return SecurityIncident.ThreatLevel.MEDIUM;
        }
    }
    
    /**
     * 이벤트 타입을 인시던트 타입으로 매핑
     */
    private SecurityIncident.IncidentType mapEventTypeToIncidentType(SecurityEvent.EventType eventType) {
        switch (eventType) {
            case BRUTE_FORCE:
            case CREDENTIAL_STUFFING:
            case INTRUSION_ATTEMPT:
                return SecurityIncident.IncidentType.INTRUSION_ATTEMPT;
            case DATA_EXFILTRATION:
                return SecurityIncident.IncidentType.DATA_EXFILTRATION;
            case PRIVILEGE_ESCALATION:
            case ACCESS_CONTROL_VIOLATION:
                return SecurityIncident.IncidentType.POLICY_VIOLATION;
            default:
                return SecurityIncident.IncidentType.SUSPICIOUS_ACTIVITY;
        }
    }

    /**
     * 정책 진화를 통한 위협 평가 개선
     * Helper를 활용하여 정책을 자율적으로 진화시킵니다.
     */
    private void evolveThreadEvaluationPolicy(SecurityEvent event, ThreatAssessment assessment) {
        if (policyEvolutionHelper == null) {
            return; // Helper가 주입되지 않은 경우 스킵
        }
        
        try {
            // 정책 학습
            String decision = assessment.getThreatLevel().toString();
            boolean outcome = assessment.getRiskScore() > threatThreshold;
            
            policyEvolutionHelper.learnFromEvent(event, decision, outcome)
                .subscribe(
                    result -> log.debug("정책 학습 완료: {}", result.getStatus()),
                    error -> log.error("정책 학습 실패", error)
                );
        } catch (Exception e) {
            log.error("정책 진화 중 오류 발생", e);
        }
    }
    
    /**
     * 학습 엔진을 통한 패턴 학습
     * 보안 이벤트로부터 패턴을 학습하고 예측을 수행합니다.
     */
    private void learnFromSecurityEvent(SecurityEvent event, String response) {
        if (learningEngineHelper == null) {
            return; // Helper가 주입되지 않은 경우 스킵
        }
        
        try {
            // 효과성 계산 (간단한 예시)
            double effectiveness = calculateResponseEffectiveness(event, response);
            
            // 학습 수행
            learningEngineHelper.learnFromEvent(event, response, effectiveness)
                .subscribe(
                    result -> {
                        log.debug("학습 완료: {} 이벤트 처리됨", result.getProcessedCount());
                        
                        // 예측 적용
                        applyLearningPrediction(event);
                    },
                    error -> log.error("학습 실패", error)
                );
        } catch (Exception e) {
            log.error("학습 엔진 처리 중 오류", e);
        }
    }
    
    /**
     * 학습된 지식을 적용하여 예측 수행
     */
    private void applyLearningPrediction(SecurityEvent event) {
        if (learningEngineHelper == null) {
            return;
        }
        
        learningEngineHelper.applyLearning(event)
            .subscribe(
                prediction -> {
                    if (prediction.getConfidence() > 0.8) {
                        log.info("높은 신뢰도 예측: {} (신뢰도: {})",
                            prediction.getPredictedResponse(), prediction.getConfidence());
                        // 예측 결과를 메모리에 저장
                        storeInMemory("prediction:" + event.getEventId(), prediction);
                    }
                },
                error -> log.error("예측 적용 실패", error)
            );
    }
    
    /**
     * 메모리 시스템에 중요 정보 저장
     */
    private void storeInMemory(String key, Object value) {
        if (memorySystemHelper == null) {
            return; // Helper가 주입되지 않은 경우 스킵
        }

        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("timestamp", LocalDateTime.now().toString());
            metadata.put("agentName", agentName);

            // SecurityIncident는 DTO로 변환하여 저장 (lazy loading 문제 방지)
            Object valueToStore = value;
            if (value instanceof SecurityIncident) {
                valueToStore = SecurityIncidentDTO.fromEntity((SecurityIncident) value);
            }

            // 작업 메모리에 저장 (빠른 접근용)
            memorySystemHelper.storeInWM(key, valueToStore, "security-plane")
                .subscribe(
                    result -> log.debug("메모리 저장 완료: {}", result.getKey()),
                    error -> log.error("메모리 저장 실패", error)
                );

            // 중요한 정보는 단기 메모리에도 저장
            if (value instanceof ThreatAssessment) {
                ThreatAssessment ta = (ThreatAssessment) value;
                if (ta.getThreatLevel() == ThreatAssessment.ThreatLevel.CRITICAL) {
                    memorySystemHelper.storeInSTM(key, valueToStore, metadata)
                        .subscribe();
                }
            }
        } catch (Exception e) {
            log.error("메모리 저장 중 오류", e);
        }
    }

    /**
     * 응답 효과성 계산 (간단한 예시)
     */
    private double calculateResponseEffectiveness(SecurityEvent event, String response) {
        // 실제로는 더 복잡한 로직이 필요
        if (response.contains("blocked") || response.contains("prevented")) {
            return 0.9;
        } else if (response.contains("alerted") || response.contains("notified")) {
            return 0.7;
        } else {
            return 0.5;
        }
    }
    

    /**
     * ThreatLevel을 Severity로 매핑
     */
    private SecurityEvent.Severity mapThreatLevelToSeverity(SecurityIncident.ThreatLevel threatLevel) {
        if (threatLevel == null) {
            return SecurityEvent.Severity.MEDIUM;
        }
        switch (threatLevel) {
            case CRITICAL:
                return SecurityEvent.Severity.CRITICAL;
            case HIGH:
                return SecurityEvent.Severity.HIGH;
            case MEDIUM:
                return SecurityEvent.Severity.MEDIUM;
            case LOW:
                return SecurityEvent.Severity.LOW;
            default:
                return SecurityEvent.Severity.INFO;
        }
    }

    /**
     * 백그라운드 모니터링 시작 - 진정한 24/7 실행
     */
    private void startBackgroundMonitoring() {
        if (backgroundTask != null && !backgroundTask.isDone()) {
            log.warn("Background monitoring already running for agent {}", agentName);
            return;
        }

        backgroundTask = CompletableFuture.runAsync(() -> {
            log.info("Starting continuous background monitoring for agent {}", agentName);

            while (running.get()) {
                try {
                    List<SecurityEvent> events = securityMonitor.pollEventsFromQueue(50, 100);

                    if (!events.isEmpty()) {
                        log.info("[SecurityPlaneAgent] Processing {} events in background for agent {}", events.size(), agentName);

                        List<CompletableFuture<Void>> futures = new ArrayList<>();

                        for (SecurityEvent event : events) {
                            CompletableFuture<Void> future = CompletableFuture.runAsync(
                                    () -> processSecurityEvent(event),
                                    backgroundExecutor
                            );
                            futures.add(future);
                        }

                        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                                .orTimeout(300, TimeUnit.SECONDS)
                                .exceptionally(ex -> {
                                    log.error("Error processing events in background", ex);
                                    return null;
                                }).join();

                        processedEvents.addAndGet(events.size());
                    }

                } catch (Exception e) {
                    log.error("Error in background monitoring for agent {}", agentName, e);
                    handleMonitoringError(e);
                }
            }

            log.info("Background monitoring stopped for agent {}", agentName);
        }, backgroundExecutor);
    }

    /**
     * Redis에서 현재 Threat Score 조회
     */
    private double getThreatScoreFromRedis(String userId) {
        try {
            String threatScoreKey = ZeroTrustRedisKeys.threatScore(userId);
            Object threatScoreObj = redisTemplate.opsForValue().get(threatScoreKey);

            if (threatScoreObj != null) {
                return Double.parseDouble(threatScoreObj.toString());
            }
        } catch (Exception e) {
            log.error("Failed to retrieve Threat Score for user: {}", userId, e);
        }

        return 0.3; // 기본값
    }

    /**
     * 백그라운드 모니터링 중지
     */
    private void stopBackgroundMonitoring() {
        if (backgroundTask != null) {
            log.info("Stopping background monitoring for agent {}", agentName);
            backgroundTask.cancel(true);
            try {
                backgroundTask.get(5, TimeUnit.SECONDS);
            } catch (Exception e) {
                log.warn("Background monitoring task did not complete cleanly for agent {}", agentName);
            }
        }
    }
    

    /**
     * 인시던트 핸들러 정리 - 메모리 누수 방지
     */
    private void cleanupIncidentHandlers() {
        try {
            log.debug("Cleaning up incident handlers for agent {}", agentName);
            
            List<String> toRemove = new ArrayList<>();
            
            activeIncidentHandlers.forEach((id, handler) -> {
                if (handler.isCompleted() || handler.isExpired()) {
                    toRemove.add(id);
                }
            });
            
            toRemove.forEach(id -> {
                activeIncidentHandlers.remove(id);
                log.debug("Removed completed/expired incident handler: {}", id);
            });
            
            if (!toRemove.isEmpty()) {
                log.info("Cleaned up {} incident handlers for agent {}", toRemove.size(), agentName);
            }
        } catch (Exception e) {
            log.error("Error cleaning up incident handlers", e);
        }
    }
    
    /**
     * Incident Handler 내부 클래스
     */
    private static class IncidentHandler {
        private final String incidentId;
        private final LocalDateTime createdAt;
        private final LocalDateTime expiresAt;
        private volatile boolean completed;
        private String soarRequestId;
        private SecurityEvent securityEvent;
        private SoarIncident soarIncident;
        private String resolutionMethod;
        private String resolvedBy;
        private LocalDateTime resolvedAt;

        public IncidentHandler(String incidentId) {
            this.incidentId = incidentId;
            this.createdAt = LocalDateTime.now();
            this.expiresAt = createdAt.plusHours(24); // 24시간 후 만료
            this.completed = false;
        }

        public boolean isCompleted() {
            return completed;
        }

        public void setCompleted(boolean completed) {
            this.completed = completed;
        }

        public boolean isExpired() {
            return LocalDateTime.now().isAfter(expiresAt);
        }

        public String getIncidentId() {
            return incidentId;
        }

        public String getSoarRequestId() {
            return soarRequestId;
        }

        public void setSoarRequestId(String soarRequestId) {
            this.soarRequestId = soarRequestId;
        }

        public LocalDateTime getCreatedAt() {
            return createdAt;
        }

        public LocalDateTime getExpiresAt() {
            return expiresAt;
        }

        public void resolveIncident(String resolvedBy, String resolutionMethod) {
            this.completed = true;
            this.resolvedBy = resolvedBy;
            this.resolutionMethod = resolutionMethod;
            this.resolvedAt = LocalDateTime.now();
        }

        // Deprecated - 이전 버전 호환성 유지
        @Deprecated
        public void resolveIncident() {
            resolveIncident("system", "auto-resolved");
        }

        public SecurityEvent getSecurityEvent() {
            return securityEvent;
        }

        public void setSecurityEvent(SecurityEvent securityEvent) {
            this.securityEvent = securityEvent;
        }

        public SoarIncident getSoarIncident() {
            return soarIncident;
        }

        public void setSoarIncident(SoarIncident soarIncident) {
            this.soarIncident = soarIncident;
        }

        public String getResolutionMethod() {
            return resolutionMethod;
        }

        public String getResolvedBy() {
            return resolvedBy;
        }

        public LocalDateTime getResolvedAt() {
            return resolvedAt;
        }

        public long getResolutionTimeMs() {
            if (resolvedAt != null) {
                return Duration.between(createdAt, resolvedAt).toMillis();
            }
            return 0;
        }
    }

    /**
     * Agent states
     */
    private enum AgentState {
        INITIALIZING,
        RUNNING,
        PAUSED,
        STOPPING,
        STOPPED,
        ERROR
    }
}