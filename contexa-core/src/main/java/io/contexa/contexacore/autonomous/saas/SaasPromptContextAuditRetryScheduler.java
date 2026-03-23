package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.springframework.scheduling.annotation.Scheduled;

public class SaasPromptContextAuditRetryScheduler {

    private final SaasPromptContextAuditDispatcher dispatcher;
    private final SaasForwardingProperties properties;

    public SaasPromptContextAuditRetryScheduler(
            SaasPromptContextAuditDispatcher dispatcher,
            SaasForwardingProperties properties) {
        this.dispatcher = dispatcher;
        this.properties = properties;
    }

    @Scheduled(fixedDelayString = "#{@saasForwardingProperties.dispatchIntervalMs}")
    public void dispatchPendingAudits() {
        if (!properties.isEnabled()) {
            return;
        }
        dispatcher.dispatchPendingBatch();
    }
}
