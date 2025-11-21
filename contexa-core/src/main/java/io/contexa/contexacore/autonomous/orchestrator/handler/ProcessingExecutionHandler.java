package io.contexa.contexacore.autonomous.orchestrator.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.event.ProcessingCompletedEvent;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventHandler;
import io.contexa.contexacore.autonomous.orchestrator.strategy.ProcessingStrategy;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.repository.SecurityIncidentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 처리 실행 핸들러
 *
 * Strategy 패턴을 사용하여 ProcessingMode에 따라
 * 적절한 처리 전략을 선택하고 실행
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j
@RequiredArgsConstructor
public class ProcessingExecutionHandler implements SecurityEventHandler {

    private final List<ProcessingStrategy> strategies;
    private final ApplicationEventPublisher eventPublisher;

    @Autowired(required = false)
    private SecurityIncidentRepository incidentRepository;

    @Value("${security.plane.agent.name:SecurityPlaneAgent-1}")
    private String agentName;

    // 전략 캐시 (성능 최적화)
    private final Map<ProcessingMode, ProcessingStrategy> strategyCache = new HashMap<>();

    @Override
    public boolean handle(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();
        ProcessingMode mode = (ProcessingMode) context.getMetadata().get("processingMode");

        if (mode == null) {
            log.info("[ProcessingExecutionHandler] No processing mode found for event: {}", event.getEventId());
            context.markAsFailed("No processing mode determined");
            return false;
        }

        log.info("[ProcessingExecutionHandler] Executing processing for event: {} with mode: {}",
            event.getEventId(), mode);

        try {
            // 전략 선택
            ProcessingStrategy strategy = selectStrategy(mode);

            if (strategy == null) {
                log.info("[ProcessingExecutionHandler] No strategy found for mode: {} - event: {}",
                    mode, event.getEventId());
                return handleNoStrategyAvailable(context, mode);
            }

            // 전략 실행
            long startTime = System.currentTimeMillis();
            ProcessingResult result = strategy.process(context);
            long executionTime = System.currentTimeMillis() - startTime;

            // 결과 처리
            handleProcessingResult(context, result, executionTime);

            // 인시던트 생성 처리
            if (result.isRequiresIncident()) {
                createIncidentFromResult(event, result, context);
            }

            // ProcessingCompletedEvent 발행 (학습 데이터 수집)
            publishProcessingCompletedEvent(event, result, mode, executionTime);

            log.info("[ProcessingExecutionHandler] Event {} processed with {} strategy - success: {}, time: {}ms",
                event.getEventId(), strategy.getName(), result.isSuccess(), executionTime);

            return result.isSuccess(); // 성공 시 계속, 실패 시 중단

        } catch (Exception e) {
            log.error("[ProcessingExecutionHandler] Error executing processing for event: {}", event.getEventId(), e);
            context.markAsFailed("Processing execution error: " + e.getMessage());
            return false;
        }
    }

    /**
     * 처리 모드에 맞는 전략 선택
     */
    private ProcessingStrategy selectStrategy(ProcessingMode mode) {
        ProcessingStrategy cached = strategyCache.get(mode);
        if (cached != null) {
            return cached;
        }

        for (ProcessingStrategy strategy : strategies) {
            if (strategy.supports(mode)) {
                strategyCache.put(mode, strategy);
                return strategy;
            }
        }

        return null;
    }

    /**
     * 전략이 없을 때 처리
     */
    private boolean handleNoStrategyAvailable(SecurityEventContext context, ProcessingMode mode) {
        log.warn("[ProcessingExecutionHandler] No strategy available for mode: {}, using fallback", mode);

        // 기본 처리 결과 생성
        ProcessingResult fallbackResult = ProcessingResult.builder()
            .success(true)
            .processingPath(ProcessingResult.ProcessingPath.BYPASS)
            .message("No specific strategy, event logged")
            .build();

        context.addMetadata("processingResult", fallbackResult);
        context.addMetadata("fallbackUsed", true);
        context.addResponseAction("FALLBACK", "Event logged without specific processing");

        // 에스컬레이션이 필요한 경우 상태 업데이트
        if (mode.needsEscalation()) {
            context.updateProcessingStatus(SecurityEventContext.ProcessingStatus.AWAITING_APPROVAL);
        }

        return true; // 처리는 계속 진행
    }

    /**
     * 처리 결과 핸들링
     */
    private void handleProcessingResult(SecurityEventContext context, ProcessingResult result, long executionTime) {
        // 컨텍스트에 결과 저장
        context.addMetadata("processingResult", result);
        context.addMetadata("processingSuccess", result.isSuccess());
        context.addMetadata("processingPath", result.getProcessingPath());
        context.addMetadata("processingExecutionTime", executionTime);

        // threatScoreAdjustment 명시적 추가 (ThreatScoreHandler에서 사용)
        double threatScoreAdjustment = result.getThreatScoreAdjustment();
        context.addMetadata("threatScoreAdjustment", threatScoreAdjustment);
        log.debug("[ProcessingExecutionHandler] ThreatScoreAdjustment added to context: {}",
            String.format("%.3f", threatScoreAdjustment));

        // 실행된 액션 기록
        if (result.getExecutedActions() != null && !result.getExecutedActions().isEmpty()) {
            for (String action : result.getExecutedActions()) {
                context.addResponseAction(action, "Executed by " + result.getProcessingPath());
            }
        }

        // 메타데이터 병합
        if (result.getMetadata() != null) {
            result.getMetadata().forEach(context::addMetadata);
        }

        // 인시던트 정보 처리
        if (result.getIncidentSeverity() != null) {
            context.addMetadata("incidentCreated", true);
            context.addMetadata("incidentSeverity", result.getIncidentSeverity());
        }

        // 상태 업데이트
        if (result.isSuccess()) {
            if (context.getProcessingStatus() != SecurityEventContext.ProcessingStatus.AWAITING_APPROVAL) {
                context.updateProcessingStatus(SecurityEventContext.ProcessingStatus.RESPONDING);
            }
        } else {
            context.markAsFailed(result.getMessage());
        }

        // 처리 메트릭 업데이트
        SecurityEventContext.ProcessingMetrics metrics = context.getProcessingMetrics();
        if (metrics == null) {
            metrics = new SecurityEventContext.ProcessingMetrics();
            context.setProcessingMetrics(metrics);
        }
        metrics.setResponseTimeMs(executionTime);
    }

    /**
     * ProcessingResult 로부터 인시던트 생성
     * SecurityPlaneAgent.createIncidentFromResult() 정확히 복제
     */
    private void createIncidentFromResult(SecurityEvent event, ProcessingResult result,
                                         SecurityEventContext context) {
        if (incidentRepository == null) {
            log.warn("[ProcessingExecutionHandler] SecurityIncidentRepository not available, cannot create incident");
            return;
        }

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
                .detectionSource(result.getProcessingPath() != null ?
                    result.getProcessingPath().toString() : "PIPELINE")
                .detectedAt(LocalDateTime.now())
                .riskScore(result.getCurrentRiskLevel())
                .autoResponseEnabled(severity == ProcessingResult.IncidentSeverity.CRITICAL)
                .build();

            // 인시던트 저장
            SecurityIncident saved = incidentRepository.save(incident);

            // 컨텍스트에 인시던트 정보 추가
            context.addMetadata("incidentId", saved.getIncidentId());
            context.addMetadata("incidentCreated", true);
            context.addMetadata("incidentSeverity", severity.toString());

            log.warn("[ProcessingExecutionHandler] Incident created: {} for event: {} - severity: {}",
                saved.getIncidentId(), event.getEventId(), severity);

            // 정책 진화 시스템 연결은 PolicyChangeEventListener가 처리
            // PolicyEvolutionEngine.evolveFromIncident 메서드는 존재하지 않음
            // 원본 코드에서도 직접 호출하지 않았음

            // 메모리 시스템 연결은 LearningSystemHandler가 처리
            // 향후 MemorySystem 클래스가 추가되면 여기서 다시 통합

        } catch (Exception e) {
            log.error("[ProcessingExecutionHandler] Failed to create incident for event: {}",
                event.getEventId(), e);
        }
    }

    /**
     * ProcessingResult.IncidentSeverity를 SecurityIncident.ThreatLevel로 변환
     */
    private SecurityIncident.ThreatLevel mapSeverityToThreatLevel(ProcessingResult.IncidentSeverity severity) {
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
     * EventType을 IncidentType으로 변환
     */
    private SecurityIncident.IncidentType mapEventTypeToIncidentType(SecurityEvent.EventType eventType) {
        switch (eventType) {
            case INTRUSION_ATTEMPT:
            case INTRUSION_SUCCESS:
                return SecurityIncident.IncidentType.INTRUSION;
            case AUTH_FAILURE:
            case AUTH_SUCCESS:
                return SecurityIncident.IncidentType.UNAUTHORIZED_ACCESS;
            case DATA_EXFILTRATION:
                return SecurityIncident.IncidentType.DATA_BREACH;
            case MALWARE_DETECTED:
                return SecurityIncident.IncidentType.MALWARE;
            case ANOMALY_DETECTED:
                return SecurityIncident.IncidentType.SUSPICIOUS_ACTIVITY;
            default:
                return SecurityIncident.IncidentType.OTHER;
        }
    }

    /**
     * ProcessingCompletedEvent 발행
     *
     * Cold/Hot Path 모든 처리 결과를 학습 시스템에 전달
     * 학습률 목표: 0.016% → 95%+ 달성
     *
     * @param event 원본 보안 이벤트
     * @param result 처리 결과
     * @param mode 처리 모드
     * @param processingTimeMs 처리 시간
     */
    private void publishProcessingCompletedEvent(SecurityEvent event, ProcessingResult result,
                                                ProcessingMode mode, long processingTimeMs) {
        try {
            // AI 분석 레벨에서 ProcessingLayer 결정
            ProcessingCompletedEvent.ProcessingLayer layer = ProcessingCompletedEvent.ProcessingLayer.UNKNOWN;

            if (result.isAiAnalysisPerformed()) {
                int aiLevel = result.getAiAnalysisLevel();
                layer = ProcessingCompletedEvent.ProcessingLayer.fromLevel(aiLevel);
            } else {
                // Hot Path는 기본적으로 Layer1 수준
                if (mode == ProcessingMode.REALTIME_BLOCK || mode == ProcessingMode.PASS_THROUGH) {
                    layer = ProcessingCompletedEvent.ProcessingLayer.LAYER1;
                }
            }

            // 이벤트 발행 (accuracy는 향후 피드백 루프 구현 시 사용)
            ProcessingCompletedEvent completedEvent = new ProcessingCompletedEvent(
                this,
                event,
                result,
                mode,
                layer,
                processingTimeMs
            );

            eventPublisher.publishEvent(completedEvent);

            log.debug("[ProcessingExecutionHandler] ProcessingCompletedEvent published - eventId: {}, mode: {}, layer: {}, highValue: {}",
                event.getEventId(), mode, layer, completedEvent.isHighValueForLearning());

        } catch (Exception e) {
            // 이벤트 발행 실패가 메인 처리 흐름을 중단하면 안 됨
            log.error("[ProcessingExecutionHandler] Failed to publish ProcessingCompletedEvent for event: {}",
                event.getEventId(), e);
        }
    }

    @Override
    public String getName() {
        return "ProcessingExecutionHandler";
    }

    @Override
    public int getOrder() {
        return 50; // RoutingDecisionHandler(40) 다음에 실행
    }
}