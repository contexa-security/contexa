package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.properties.SaasForwardingProperties;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;

public class SaasDecisionFeedbackRetryScheduler {

    private final SaasDecisionFeedbackDispatcher dispatcher;
    private final SaasForwardingProperties properties;

    public SaasDecisionFeedbackRetryScheduler(
            SaasDecisionFeedbackDispatcher dispatcher,
            SaasForwardingProperties properties) {
        this.dispatcher = dispatcher;
        this.properties = properties;
    }

    @Scheduled(fixedDelayString = "${contexa.saas.dispatch-interval-ms:30000}")
    @SchedulerLock(name = "saasDecisionFeedbackRetry", lockAtMostFor = "PT5M", lockAtLeastFor = "PT5S")
    public void retryPendingDispatches() {
        if (!properties.isEnabled() || !properties.getDecisionFeedback().isEnabled()) {
            return;
        }
        dispatcher.dispatchPendingBatch();
    }
}
