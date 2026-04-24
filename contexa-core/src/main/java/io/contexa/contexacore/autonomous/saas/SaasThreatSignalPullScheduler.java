package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.properties.SaasForwardingProperties;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;

public class SaasThreatSignalPullScheduler {

    private final SaasThreatIntelligenceService threatIntelligenceService;
    private final SaasForwardingProperties properties;

    public SaasThreatSignalPullScheduler(
            SaasThreatIntelligenceService threatIntelligenceService,
            SaasForwardingProperties properties) {
        this.threatIntelligenceService = threatIntelligenceService;
        this.properties = properties;
    }

    @Scheduled(
            initialDelayString = "${contexa.saas.threat-intelligence.initial-delay-ms:0}",
            fixedDelayString = "${contexa.saas.threat-intelligence.pull-interval-ms:3600000}")
    @SchedulerLock(name = "saasThreatSignalPull", lockAtMostFor = "PT10M", lockAtLeastFor = "PT10S")
    public void refreshThreatSignals() {
        if (!properties.isEnabled()
                || properties.getThreatIntelligence() == null
                || !properties.getThreatIntelligence().isEnabled()) {
            return;
        }
        threatIntelligenceService.refresh();
    }
}
