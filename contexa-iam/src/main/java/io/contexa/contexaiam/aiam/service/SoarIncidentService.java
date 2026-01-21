package io.contexa.contexaiam.aiam.service;

import io.contexa.contexacore.domain.entity.SoarIncident;
import io.contexa.contexacore.domain.SoarIncidentStatus;
import io.contexa.contexacore.repository.SoarIncidentRepository;
import io.contexa.contexacore.autonomous.event.IncidentCompletedEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
public class SoarIncidentService {
    private final SoarIncidentRepository incidentRepository;
    private final ApplicationEventPublisher eventPublisher;

    public SoarIncidentService(SoarIncidentRepository incidentRepository,
                              ApplicationEventPublisher eventPublisher) {
        this.incidentRepository = incidentRepository;
        this.eventPublisher = eventPublisher;
    }

    @Transactional(readOnly = true)
    public List<SoarIncident> getActiveIncidents() {
        return incidentRepository.findByStatusInOrderByUpdatedAtDesc(
                List.of(
                        SoarIncidentStatus.NEW, SoarIncidentStatus.TRIAGE, SoarIncidentStatus.INVESTIGATION,
                        SoarIncidentStatus.PLANNING, SoarIncidentStatus.PENDING_APPROVAL, SoarIncidentStatus.EXECUTION
                )
        );
    }

    @Transactional(readOnly = true)
    public SoarIncident getIncident(UUID incidentId) {
        return incidentRepository.findById(incidentId)
                .orElseThrow(() -> new IllegalArgumentException("Incident not found: " + incidentId));
    }

    @Transactional
    public SoarIncident createIncident(String title, String playbookId, Map<String, Object> eventData) {
        SoarIncident incident = new SoarIncident();
        incident.setTitle(title);
        incident.setStatus(SoarIncidentStatus.NEW);
        incident.addHistoryLog("Incident created with title: " + title);

        SoarIncident savedIncident = incidentRepository.save(incident);

        return savedIncident;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void updateIncidentStatus(UUID incidentId, SoarIncidentStatus status, String logMessage) {
        incidentRepository.findById(incidentId).ifPresent(incident -> {
            incident.setStatus(status);
            incident.addHistoryLog(logMessage);
            incidentRepository.save(incident);
        });
    }

    @Transactional
    public void completeIncident(UUID incidentId, String resolvedBy, String resolutionMethod, boolean wasSuccessful) {
        SoarIncident incident = incidentRepository.findById(incidentId)
            .orElseThrow(() -> new IllegalArgumentException("Incident not found: " + incidentId));

        SoarIncidentStatus finalStatus = wasSuccessful ?
            SoarIncidentStatus.COMPLETED : SoarIncidentStatus.FAILED;

        incident.setStatus(finalStatus);
        incident.addHistoryLog(String.format("Incident %s by %s using %s",
            wasSuccessful ? "resolved" : "failed", resolvedBy, resolutionMethod));

        incidentRepository.save(incident);

        publishIncidentCompletedEvent(incident, resolvedBy, resolutionMethod, wasSuccessful);
    }

    private void publishIncidentCompletedEvent(SoarIncident incident, String resolvedBy,
                                              String resolutionMethod, boolean wasSuccessful) {
        
        IncidentCompletedEvent event = new IncidentCompletedEvent(
            this, incident, resolvedBy, resolutionMethod, wasSuccessful);

        eventPublisher.publishEvent(event);

            }
}