package io.contexa.contexacore.autonomous.processor;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Slf4j
public class EventNormalizer implements EventProcessor<SecurityEvent> {

    @Override
    public SecurityEvent process(SecurityEvent event) {
        if (event == null) {
            log.warn("Null event received for normalization");
            return null;
        }

        normalizeTimestamp(event);

        normalizeSeverity(event);

        normalizeIpAddress(event);

        normalizeEventId(event);

        normalizeSource(event);

        return event;
    }

    private void normalizeTimestamp(SecurityEvent event) {
        if (event.getTimestamp() == null) {
            event.setTimestamp(LocalDateTime.now());
                    }
    }

    private void normalizeSeverity(SecurityEvent event) {
        if (event.getSeverity() == null) {
            
            event.setSeverity(SecurityEvent.Severity.INFO);
                    }
    }

    private void normalizeIpAddress(SecurityEvent event) {
        String sourceIp = event.getSourceIp();
        if (sourceIp != null && sourceIp.contains(",")) {
            
            String normalizedIp = sourceIp.split(",")[0].trim();
            event.setSourceIp(normalizedIp);
                    }

        if (sourceIp != null && sourceIp.contains("::")) {
            event.setSourceIp(normalizeIpv6(sourceIp));
        }
    }

    private String normalizeIpv6(String ipv6) {
        
        if ("::1".equals(ipv6) || "0:0:0:0:0:0:0:1".equals(ipv6)) {
            return "127.0.0.1"; 
        }
        return ipv6.toLowerCase();
    }

    private void normalizeEventId(SecurityEvent event) {
        if (event.getEventId() == null || event.getEventId().isEmpty()) {
            String newEventId = java.util.UUID.randomUUID().toString();
            event.setEventId(newEventId);
                    }
    }

    private void normalizeSource(SecurityEvent event) {
        if (event.getSource() == null) {
            event.setSource(SecurityEvent.EventSource.UNKNOWN);
                    }
    }

    @Override
    public int getPriority() {
        return 100;
    }

    @Override
    public String getName() {
        return "EventNormalizer";
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}