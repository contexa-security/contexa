package io.contexa.contexacore.autonomous.orchestrator;

import io.contexa.contexacore.autonomous.ISecurityPlaneAgent;
import io.contexa.contexacore.autonomous.event.IncidentCompletedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

/**
 * Security Plane 이벤트 리스너
 *
 * SecurityPlaneAgent와 분리하여 이벤트 처리를 전담
 * 프록시 문제를 방지하고 단일 책임 원칙을 준수
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SecurityPlaneEventListener {

    private final ISecurityPlaneAgent securityPlaneAgent;

    /**
     * IncidentCompletedEvent 리스너 - SOAR → Evolution 연결
     *
     * SOAR 시스템에서 인시던트가 완료되면 Security Plane Agent에 전달하여
     * 정책 진화 및 학습 프로세스를 트리거
     */
    @EventListener
    @Async
    public void onIncidentCompleted(IncidentCompletedEvent event) {
        try {
            String incidentId = event.getIncident().getId().toString();
            String resolvedBy = event.getResolvedBy();
            String resolutionMethod = event.getResolutionMethod();
            boolean wasSuccessful = event.wasSuccessful();

            log.info("[SecurityPlaneEventListener] Received IncidentCompletedEvent: {} resolved by {} using {} (success: {})",
                incidentId, resolvedBy, resolutionMethod, wasSuccessful);

            // SecurityPlaneAgent의 인시던트 해결 메소드 호출
            // 이벤트 발행 및 정책 진화 프로세스 트리거
            securityPlaneAgent.resolveIncident(incidentId, resolvedBy, resolutionMethod, wasSuccessful);

            log.debug("[SecurityPlaneEventListener] Successfully delegated incident completion to SecurityPlaneAgent");

        } catch (Exception e) {
            log.error("[SecurityPlaneEventListener] Failed to handle IncidentCompletedEvent: {}", event, e);
        }
    }
}