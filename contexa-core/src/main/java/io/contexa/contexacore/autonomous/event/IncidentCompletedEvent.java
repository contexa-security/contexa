package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacore.domain.entity.SoarIncident;
import org.springframework.context.ApplicationEvent;


public class IncidentCompletedEvent extends ApplicationEvent {

    private final SoarIncident incident;
    private final String resolvedBy;
    private final String resolutionMethod;
    private final boolean wasSuccessful;

    
    public IncidentCompletedEvent(Object source, SoarIncident incident,
                                 String resolvedBy, String resolutionMethod,
                                 boolean wasSuccessful) {
        super(source);
        this.incident = incident;
        this.resolvedBy = resolvedBy;
        this.resolutionMethod = resolutionMethod;
        this.wasSuccessful = wasSuccessful;
    }

    
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