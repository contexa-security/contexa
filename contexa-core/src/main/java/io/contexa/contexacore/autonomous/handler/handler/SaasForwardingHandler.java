package io.contexa.contexacore.autonomous.handler.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.saas.SaasDecisionOutboxService;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class SaasForwardingHandler implements SecurityEventHandler {

    private final SaasDecisionOutboxService outboxService;
    private final SaasForwardingProperties properties;

    @Override
    public boolean canHandle(SecurityEventContext context) {
        if (context == null || !properties.isEnabled()) {
            return false;
        }
        Object resultObject = context.getMetadata().get("processingResult");
        if (!(resultObject instanceof ProcessingResult result) || !result.isSuccess()) {
            return false;
        }
        return "BLOCK".equalsIgnoreCase(result.getAction())
                || "CHALLENGE".equalsIgnoreCase(result.getAction());
    }

    @Override
    public boolean handle(SecurityEventContext context) {
        try {
            outboxService.capture(context);
            return true;
        }
        catch (Exception e) {
            log.error("[SaasForwardingHandler] Failed to capture SaaS forwarding payload: eventId={}",
                    context.getSecurityEvent() != null ? context.getSecurityEvent().getEventId() : "unknown", e);
            return true;
        }
    }

    @Override
    public String getName() {
        return "SaasForwardingHandler";
    }

    @Override
    public int getOrder() {
        return 65;
    }
}
