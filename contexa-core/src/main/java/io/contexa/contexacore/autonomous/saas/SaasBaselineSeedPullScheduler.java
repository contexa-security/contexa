package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.properties.SaasForwardingProperties;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;

public class SaasBaselineSeedPullScheduler {

    private final SaasBaselineSeedService baselineSeedService;
    private final SaasForwardingProperties properties;

    public SaasBaselineSeedPullScheduler(
            SaasBaselineSeedService baselineSeedService,
            SaasForwardingProperties properties) {
        this.baselineSeedService = baselineSeedService;
        this.properties = properties;
    }

    @Scheduled(
            initialDelayString = "${contexa.saas.baseline-signal.seed-initial-delay-ms:120000}",
            fixedDelayString = "${contexa.saas.baseline-signal.seed-pull-interval-ms:3600000}")
    @SchedulerLock(name = "saasBaselineSeedPull", lockAtMostFor = "PT10M", lockAtLeastFor = "PT10S")
    public void refreshSeed() {
        if (!properties.isEnabled()
                || properties.getBaselineSignal() == null
                || !properties.getBaselineSignal().isEnabled()) {
            return;
        }
        baselineSeedService.refresh();
    }
}
