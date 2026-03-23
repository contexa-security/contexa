package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.springframework.scheduling.annotation.Scheduled;

public class SaasBaselineSignalScheduler {

    private final BaselineSignalAggregationService aggregationService;
    private final SaasBaselineSignalDispatcher dispatcher;
    private final SaasForwardingProperties properties;

    public SaasBaselineSignalScheduler(
            BaselineSignalAggregationService aggregationService,
            SaasBaselineSignalDispatcher dispatcher,
            SaasForwardingProperties properties) {
        this.aggregationService = aggregationService;
        this.dispatcher = dispatcher;
        this.properties = properties;
    }

    @Scheduled(
            initialDelayString = "${contexa.saas.baseline-signal.initial-delay-ms:300000}",
            fixedDelayString = "${contexa.saas.baseline-signal.publish-interval-ms:86400000}")
    public void captureAndDispatch() {
        if (!properties.isEnabled()
                || properties.getBaselineSignal() == null
                || !properties.getBaselineSignal().isEnabled()) {
            return;
        }
        aggregationService.captureCurrentPeriod();
        dispatcher.dispatchPendingBatch();
    }
}
