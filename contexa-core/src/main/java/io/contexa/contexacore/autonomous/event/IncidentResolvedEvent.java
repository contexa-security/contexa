package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacore.domain.entity.SoarIncident;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import org.springframework.context.ApplicationEvent;

/**
 * 보안 사건이 해결되었을 때 발생하는 이벤트
 *
 * 이 이벤트는 자율 학습 시스템이 사건 해결 패턴을 학습하고
 * 정책을 진화시키는 트리거 역할을 합니다.
 *
 * @author contexa
 * @since 1.0.0
 */
public class IncidentResolvedEvent extends ApplicationEvent {

    private final String incidentId;
    private final SoarIncident incident;
    private final SecurityEvent securityEvent;
    private final String resolvedBy;
    private final String resolutionMethod;
    private final long resolutionTimeMs;
    private final boolean wasSuccessful;

    /**
     * 사건 해결 이벤트 생성자
     *
     * @param source 이벤트 발생 소스
     * @param incidentId 사건 ID
     * @param incident SOAR 사건 정보
     * @param securityEvent 원본 보안 이벤트
     * @param resolvedBy 해결 주체 (system/human/ai)
     * @param resolutionMethod 해결 방법
     * @param resolutionTimeMs 해결 소요 시간(밀리초)
     * @param wasSuccessful 성공적으로 해결되었는지 여부
     */
    public IncidentResolvedEvent(Object source, String incidentId, SoarIncident incident,
                                SecurityEvent securityEvent, String resolvedBy,
                                String resolutionMethod, long resolutionTimeMs,
                                boolean wasSuccessful) {
        super(source);
        this.incidentId = incidentId;
        this.incident = incident;
        this.securityEvent = securityEvent;
        this.resolvedBy = resolvedBy;
        this.resolutionMethod = resolutionMethod;
        this.resolutionTimeMs = resolutionTimeMs;
        this.wasSuccessful = wasSuccessful;
    }

    // Getters
    public String getIncidentId() {
        return incidentId;
    }

    public SoarIncident getIncident() {
        return incident;
    }

    public SecurityEvent getSecurityEvent() {
        return securityEvent;
    }

    public String getResolvedBy() {
        return resolvedBy;
    }

    public String getResolutionMethod() {
        return resolutionMethod;
    }

    public long getResolutionTimeMs() {
        return resolutionTimeMs;
    }

    public boolean wasSuccessful() {
        return wasSuccessful;
    }

    @Override
    public String toString() {
        return String.format("IncidentResolvedEvent[id=%s, resolvedBy=%s, method=%s, successful=%s, timeMs=%d]",
            incidentId, resolvedBy, resolutionMethod, wasSuccessful, resolutionTimeMs);
    }
}