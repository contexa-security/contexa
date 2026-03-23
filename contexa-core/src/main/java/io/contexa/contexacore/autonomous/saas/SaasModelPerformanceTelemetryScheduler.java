package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.springframework.scheduling.annotation.Scheduled;

public class SaasModelPerformanceTelemetryScheduler {

    private final SaasModelPerformanceTelemetryDispatcher dispatcher;
    private final SaasForwardingProperties properties;

    public SaasModelPerformanceTelemetryScheduler(
            SaasModelPerformanceTelemetryDispatcher dispatcher,
            SaasForwardingProperties properties) {
        this.dispatcher = dispatcher;
        this.properties = properties;
    }

    @Scheduled(
            initialDelayString = "${contexa.saas.performance-telemetry.initial-delay-ms:60000}",
            fixedDelayString = "${contexa.saas.performance-telemetry.publish-interval-ms:3600000}")
    public void dispatchCompletedPeriods() {
        if (!properties.isEnabled()
                || properties.getPerformanceTelemetry() == null
                || !properties.getPerformanceTelemetry().isEnabled()) {
            return;
        }
        dispatcher.dispatchPendingBatch();
    }
}
