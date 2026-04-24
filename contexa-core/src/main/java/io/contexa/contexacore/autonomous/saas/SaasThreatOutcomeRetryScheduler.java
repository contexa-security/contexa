package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.properties.SaasForwardingProperties;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;

public class SaasThreatOutcomeRetryScheduler {

    private final SaasThreatOutcomeDispatcher dispatcher;
    private final SaasForwardingProperties properties;

    public SaasThreatOutcomeRetryScheduler(
            SaasThreatOutcomeDispatcher dispatcher,
            SaasForwardingProperties properties) {
        this.dispatcher = dispatcher;
        this.properties = properties;
    }

    @Scheduled(fixedDelayString = "${contexa.saas.dispatch-interval-ms:30000}")
    @SchedulerLock(name = "saasThreatOutcomeRetry", lockAtMostFor = "PT5M", lockAtLeastFor = "PT5S")
    public void dispatchPendingThreatOutcomes() {
        if (!properties.isEnabled()
                || properties.getThreatOutcome() == null
                || !properties.getThreatOutcome().isEnabled()) {
            return;
        }
        dispatcher.dispatchPendingBatch();
    }
}