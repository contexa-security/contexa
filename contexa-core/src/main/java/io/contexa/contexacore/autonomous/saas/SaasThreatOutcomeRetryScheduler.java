package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.properties.SaasForwardingProperties;
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
    public void dispatchPendingThreatOutcomes() {
        if (!properties.isEnabled()
                || properties.getThreatOutcome() == null
                || !properties.getThreatOutcome().isEnabled()) {
            return;
        }
        dispatcher.dispatchPendingBatch();
    }
}