package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.domain.entity.ThreatIndicator;

import java.util.List;
import java.util.Map;

public interface ISoarContextProvider {

    SoarContext createContextFromIncident(SecurityIncident incident);

    SoarContext createContextFromEvents(List<SecurityEvent> events);

    SoarContext createContextFromThreatIndicators(List<ThreatIndicator> indicators);

    SoarContext enrichContext(SoarContext context, Map<String, Object> additionalInfo);

    SoarContext createEmergencyContext(String description, String severity);
}