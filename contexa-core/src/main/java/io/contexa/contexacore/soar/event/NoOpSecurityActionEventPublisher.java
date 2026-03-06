package io.contexa.contexacore.soar.event;

import io.contexa.contexacommon.soar.event.SecurityActionEvent;
import io.contexa.contexacommon.soar.event.SecurityActionEventPublisher;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class NoOpSecurityActionEventPublisher implements SecurityActionEventPublisher {

    private boolean logged = false;

    @Override
    public void publish(SecurityActionEvent event) {
        if (!logged) {
            log.error("[NoOpActionPublisher] SOAR auto-response is disabled in standalone mode");
            logged = true;
        }
    }
}
