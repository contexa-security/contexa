package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;


public interface SecurityEventPublisher {

    
    void publishGenericSecurityEvent(ZeroTrustSpringEvent event);
}
