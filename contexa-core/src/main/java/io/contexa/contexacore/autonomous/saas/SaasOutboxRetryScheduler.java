package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.springframework.scheduling.annotation.Scheduled;

public class SaasOutboxRetryScheduler {

    private final SaasDecisionDispatcher dispatcher;
    private final SaasForwardingProperties properties;

    public SaasOutboxRetryScheduler(
            SaasDecisionDispatcher dispatcher,
            SaasForwardingProperties properties) {
        this.dispatcher = dispatcher;
        this.properties = properties;
    }

    @Scheduled(fixedDelayString = "${contexa.saas.dispatch-interval-ms:30000}")
    public void retryPendingDispatches() {
        if (!properties.isEnabled()) {
            return;
        }
        dispatcher.dispatchPendingBatch();
    }
}
