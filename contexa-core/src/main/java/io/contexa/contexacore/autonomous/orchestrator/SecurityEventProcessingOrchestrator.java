package io.contexa.contexacore.autonomous.orchestrator;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * 보안 이벤트 처리 오케스트레이터
 *
 * SecurityPlaneAgent의 복잡한 processSecurityEvent 메서드를
 * 클린 코드 원칙에 따라 파이프라인 패턴으로 분리합니다.
 *
 * 역할:
 * - 보안 이벤트 처리 파이프라인 관리
 * - 핸들러 체인 실행 및 조정
 * - 에러 처리 및 복구
 * - 처리 메트릭 수집
 *
 * 장점:
 * - SRP (Single Responsibility Principle) 준수
 * - OCP (Open/Closed Principle) 준수
 * - 테스트 용이성 향상
 * - 확장성 및 유지보수성 개선
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j
@RequiredArgsConstructor
public class SecurityEventProcessingOrchestrator {

    private final List<SecurityEventHandler> handlers;

    /**
     * 보안 이벤트 처리 실행
     *
     * 기존 SecurityPlaneAgent.processSecurityEvent()의 복잡한 로직을
     * 단순한 파이프라인 실행으로 변환합니다.
     *
     * @param event 처리할 보안 이벤트
     * @return 처리 완료된 컨텍스트
     */
    public SecurityEventContext process(SecurityEvent event) {
        long startTime = System.currentTimeMillis();

        // 1. 컨텍스트 생성 (기존 SecurityEventContext 활용)
        SecurityEventContext context = SecurityEventContext.builder()
            .securityEvent(event)
            .processingStatus(SecurityEventContext.ProcessingStatus.PENDING)
            .createdAt(LocalDateTime.now())
            .build();

        // 메타데이터 추가
        context.addMetadata("startTime", startTime);
        context.addMetadata("agentId", "security-plane-agent");
        context.addMetadata("orchestratorVersion", "1.0");

        try {
            // 2. 핸들러 체인 실행
            List<SecurityEventHandler> sortedHandlers = getSortedHandlers();

            log.info("[SecurityEventProcessingOrchestrator] Starting event processing - eventId: {}, handlers: {}",
                event.getEventId(), sortedHandlers.size());

            for (SecurityEventHandler handler : sortedHandlers) {
                if (!executeHandler(handler, context)) {
                    log.info("[SecurityEventProcessingOrchestrator] Processing chain stopped by handler: {}",
                        handler.getName());
                    break;
                }
            }

            // 3. 처리 완료 처리
            if (context.getProcessingStatus() != SecurityEventContext.ProcessingStatus.FAILED) {
                context.markAsCompleted();
            }

        } catch (Exception e) {
            log.error("[Orchestrator] Unexpected error in processing pipeline - eventId: {}",
                event.getEventId(), e);
            context.markAsFailed("Orchestrator error: " + e.getMessage());
        } finally {
            // 4. 처리 메트릭 기록
            recordProcessingMetrics(context, startTime);
        }

        return context;
    }

    /**
     * 개별 핸들러 실행
     *
     * @param handler 실행할 핸들러
     * @param context 보안 이벤트 컨텍스트
     * @return 계속 진행 여부
     */
    private boolean executeHandler(SecurityEventHandler handler, SecurityEventContext context) {
        // 핸들러 실행 가능 여부 확인
        if (!handler.canHandle(context)) {
            log.debug("[Orchestrator] Handler {} skipped - cannot handle current context",
                handler.getName());
            return true; // 다음 핸들러로 계속 진행
        }

        try {
            long handlerStartTime = System.currentTimeMillis();

            log.info("[SecurityEventProcessingOrchestrator] Executing handler: {} for event: {}",
                handler.getName(), context.getSecurityEvent().getEventId());

            // 핸들러 실행
            boolean continueChain = handler.handle(context);

            // 핸들러 실행 시간 기록
            long handlerTime = System.currentTimeMillis() - handlerStartTime;
            context.addMetadata(handler.getName() + "_executionTime", handlerTime);

            log.info("[SecurityEventProcessingOrchestrator] Handler {} completed in {}ms - continue: {}",
                handler.getName(), handlerTime, continueChain);

            return continueChain;

        } catch (Exception e) {
            log.error("[Orchestrator] Error in handler {} for event: {}",
                handler.getName(), context.getSecurityEvent().getEventId(), e);

            // 핸들러 에러 처리
            handler.handleError(context, e);

            // 핸들러 에러는 체인을 중단하지 않음 (복구 가능)
            return true;
        }
    }

    /**
     * 핸들러 정렬 (실행 순서에 따라)
     *
     * @return 정렬된 핸들러 리스트
     */
    private List<SecurityEventHandler> getSortedHandlers() {
        List<SecurityEventHandler> sorted = new ArrayList<>(handlers);
        sorted.sort(Comparator.comparingInt(SecurityEventHandler::getOrder));
        return sorted;
    }

    /**
     * 처리 메트릭 기록
     *
     * @param context 보안 이벤트 컨텍스트
     * @param startTime 처리 시작 시간
     */
    private void recordProcessingMetrics(SecurityEventContext context, long startTime) {
        long totalTime = System.currentTimeMillis() - startTime;

        SecurityEventContext.ProcessingMetrics metrics = context.getProcessingMetrics();
        if (metrics == null) {
            metrics = new SecurityEventContext.ProcessingMetrics();
            context.setProcessingMetrics(metrics);
        }

        metrics.setTotalTimeMs(totalTime);
        metrics.setProcessingNode(System.getProperty("node.id", "local"));

        context.addMetadata("totalProcessingTime", totalTime);
        context.addMetadata("completedAt", LocalDateTime.now());

        log.info("[Orchestrator] Event processing completed - eventId: {}, status: {}, totalTime: {}ms",
            context.getSecurityEvent().getEventId(),
            context.getProcessingStatus(),
            totalTime);
    }

    /**
     * 핸들러 동적 추가
     *
     * @param handler 추가할 핸들러
     */
    public void addHandler(SecurityEventHandler handler) {
        if (handler != null && !handlers.contains(handler)) {
            handlers.add(handler);
            log.info("[Orchestrator] Handler added: {}", handler.getName());
        }
    }

    /**
     * 핸들러 동적 제거
     *
     * @param handler 제거할 핸들러
     */
    public void removeHandler(SecurityEventHandler handler) {
        if (handler != null && handlers.remove(handler)) {
            log.info("[Orchestrator] Handler removed: {}", handler.getName());
        }
    }

    /**
     * 현재 등록된 핸들러 목록 조회
     *
     * @return 핸들러 이름 목록
     */
    public List<String> getHandlerNames() {
        return getSortedHandlers().stream()
            .map(SecurityEventHandler::getName)
            .toList();
    }
}