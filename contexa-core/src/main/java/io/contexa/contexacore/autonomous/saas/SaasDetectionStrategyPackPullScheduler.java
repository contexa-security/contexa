package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.springframework.scheduling.annotation.Scheduled;

public class SaasDetectionStrategyPackPullScheduler {

    private final SaasDetectionStrategyPackService detectionStrategyPackService;
    private final SaasForwardingProperties properties;

    public SaasDetectionStrategyPackPullScheduler(
            SaasDetectionStrategyPackService detectionStrategyPackService,
            SaasForwardingProperties properties) {
        this.detectionStrategyPackService = detectionStrategyPackService;
        this.properties = properties;
    }

    @Scheduled(
            initialDelayString = "",
            fixedDelayString = "")
    public void refreshDetectionStrategyPack() {
        if (!properties.isEnabled()
                || properties.getDetectionStrategy() == null
                || !properties.getDetectionStrategy().isEnabled()) {
            return;
        }
        detectionStrategyPackService.refresh();
    }
}