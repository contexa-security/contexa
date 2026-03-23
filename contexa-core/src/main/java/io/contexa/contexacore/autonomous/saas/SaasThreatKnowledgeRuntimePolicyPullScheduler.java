package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.springframework.scheduling.annotation.Scheduled;

public class SaasThreatKnowledgeRuntimePolicyPullScheduler {

    private final SaasThreatKnowledgeRuntimePolicyService runtimePolicyService;
    private final SaasForwardingProperties properties;

    public SaasThreatKnowledgeRuntimePolicyPullScheduler(
            SaasThreatKnowledgeRuntimePolicyService runtimePolicyService,
            SaasForwardingProperties properties) {
        this.runtimePolicyService = runtimePolicyService;
        this.properties = properties;
    }

    @Scheduled(
            initialDelayString = "${contexa.saas.threat-knowledge.initial-delay-ms:0}",
            fixedDelayString = "${contexa.saas.threat-knowledge.pull-interval-ms:3600000}")
    public void refreshThreatKnowledgeRuntimePolicy() {
        if (!properties.isEnabled()
                || properties.getThreatKnowledge() == null
                || !properties.getThreatKnowledge().isEnabled()) {
            return;
        }
        runtimePolicyService.refresh();
    }
}
