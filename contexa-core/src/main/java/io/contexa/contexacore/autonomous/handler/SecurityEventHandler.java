package io.contexa.contexacore.autonomous.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEventContext;

public interface SecurityEventHandler {

    boolean handle(SecurityEventContext context);

    String getName();

    default int getOrder() {
        return 100;
    }

    default boolean canHandle(SecurityEventContext context) {
        return context != null &&
               context.getSecurityEvent() != null &&
               context.getProcessingStatus() != SecurityEventContext.ProcessingStatus.FAILED;
    }

    default void handleError(SecurityEventContext context, Exception error) {
        context.markAsFailed(String.format("[%s] %s", getName(), error.getMessage()));
    }
}