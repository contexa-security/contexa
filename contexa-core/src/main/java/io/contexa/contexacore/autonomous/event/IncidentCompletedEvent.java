package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacore.domain.entity.SoarIncident;
import org.springframework.context.ApplicationEvent;

/**
 * SOAR 인시던트가 완료되었을 때 발생하는 이벤트
 *
 * 이 이벤트는 SoarIncidentService에서 발행되어
 * SecurityPlaneAgent로 전달되어 IncidentResolvedEvent로 변환됩니다.
 *
 * @author contexa
 * @since 1.0.0
 */
public class IncidentCompletedEvent extends ApplicationEvent {

    private final SoarIncident incident;
    private final String resolvedBy;
    private final String resolutionMethod;
    private final boolean wasSuccessful;

    /**
     * 인시던트 완료 이벤트 생성자
     *
     * @param source 이벤트 발생 소스
     * @param incident SOAR 인시던트
     * @param resolvedBy 해결 주체
     * @param resolutionMethod 해결 방법
     * @param wasSuccessful 성공 여부
     */
    public IncidentCompletedEvent(Object source, SoarIncident incident,
                                 String resolvedBy, String resolutionMethod,
                                 boolean wasSuccessful) {
        super(source);
        this.incident = incident;
        this.resolvedBy = resolvedBy;
        this.resolutionMethod = resolutionMethod;
        this.wasSuccessful = wasSuccessful;
    }

    // Getters
    public SoarIncident getIncident() {
        return incident;
    }

    public String getResolvedBy() {
        return resolvedBy;
    }

    public String getResolutionMethod() {
        return resolutionMethod;
    }

    public boolean wasSuccessful() {
        return wasSuccessful;
    }

    @Override
    public String toString() {
        return String.format("IncidentCompletedEvent[id=%s, resolvedBy=%s, method=%s, successful=%s]",
            incident.getId(), resolvedBy, resolutionMethod, wasSuccessful);
    }
}