package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacore.domain.entity.SoarIncident;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import org.springframework.context.ApplicationEvent;

public class IncidentResolvedEvent extends ApplicationEvent {

    private final String incidentId;
    private final SoarIncident incident;
    private final SecurityEvent securityEvent;
    private final String resolvedBy;
    private final String resolutionMethod;
    private final long resolutionTimeMs;
    private final boolean wasSuccessful;

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