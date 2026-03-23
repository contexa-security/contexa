package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.springframework.scheduling.annotation.Scheduled;

public class SaasThreatKnowledgePackPullScheduler {

    private final SaasThreatKnowledgePackService threatKnowledgePackService;
    private final SaasForwardingProperties properties;

    public SaasThreatKnowledgePackPullScheduler(
            SaasThreatKnowledgePackService threatKnowledgePackService,
            SaasForwardingProperties properties) {
        this.threatKnowledgePackService = threatKnowledgePackService;
        this.properties = properties;
    }

    @Scheduled(
            initialDelayString = "${contexa.saas.threat-knowledge.initial-delay-ms:0}",
            fixedDelayString = "${contexa.saas.threat-knowledge.pull-interval-ms:3600000}")
    public void refreshThreatKnowledgePack() {
        if (!properties.isEnabled()
                || properties.getThreatKnowledge() == null
                || !properties.getThreatKnowledge().isEnabled()) {
            return;
        }
        threatKnowledgePackService.refresh();
    }
}